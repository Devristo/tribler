"""
Created on 3 jun. 2013

@author: Chris
"""
import logging
logger = logging.getLogger(__name__)

import Socks5
from Socks5.structs import MethodRequest, Request

DEBUG = True


class ConnectionState(object):
    (BEFORE_METHOD_REQUEST, METHOD_REQUESTED, CONNECTED, PROXY_REQUEST_RECEIVED, PROXY_REQUEST_ACCEPTED,
     TCP_RELAY) = range(6)


class Socks5Connection(object):
    """
    SOCKS5 TCP Connection handler

    Supports a subset of the SOCKS5 protocol, no authentication and no support for TCP BIND requests
    """
    def __init__(self, single_socket, connection_handler):
        self.state = ConnectionState.BEFORE_METHOD_REQUEST

        self.single_socket = single_socket
        """:type : SingleSocket"""

        self.connection_handler = connection_handler
        """:type : Socks5Handler """

        self.buffer = ''

        self.tcp_relay = None

    def data_came_in(self, data):
        """
        Called by the TcpConnectionHandler when new data has been received.

        Processes the incoming buffer by attempting to read messages defined in the SOCKS5 protocol

        :param data: the data received
        :return: None
        """

        if len(self.buffer) == 0:
            self.buffer = data
        else:
            self.buffer = self.buffer + data

        self._process_buffer()

    def _try_handshake(self):

        # Try to read a HANDSHAKE request
        offset, request = Socks5.structs.decode_methods_request(0, self.buffer)

        # No (complete) HANDSHAKE received, so dont do anything
        if request is None:
            return None

        # Consume the buffer
        self.buffer = self.buffer[offset:]

        assert isinstance(request, MethodRequest)

        # Only accept NO AUTH
        if request.version != 0x05 or len({0x00, 0x01, 0x02}.difference(request.methods)) == 2:
            logger.info("Client has sent INVALID METHOD REQUEST")
            self.buffer = ''
            self.close()
            return

        logger.info("Client has sent METHOD REQUEST")

        # Respond that we would like to use NO AUTHENTICATION (0x00)
        response = Socks5.structs.encode_method_selection_message(Socks5.structs.SOCKS_VERSION, 0x00)
        self.write(response)

        # We should be connected now, the next incoming message will be a REQUEST
        self.state = ConnectionState.CONNECTED

    def _try_tcp_relay(self):
        """
        Forward the complete buffer to the paired TCP socket

        :return: None
        """
        logger.info("Relaying TCP data")
        self.tcp_relay.sendall(self.buffer)
        self.buffer = ''

    def _try_request(self):
        """
        Try to consume a REQUEST message and respond whether we will accept the request.

        Will setup a TCP relay or an UDP socket to accommodate TCP RELAY and UDP ASSOCIATE requests. After a TCP relay
        is set up the handler will deactivate itself and change the Connection to a TcpRelayConnection. Further data will be
        passed on to that handler.

        :return: None
        """
        offset, request = Socks5.structs.decode_request(0, self.buffer)

        if request is None:
            return None

        self.buffer = self.buffer[offset:]

        assert isinstance(request, Request)
        logger.debug("Client has sent PROXY REQUEST")

        self.state = ConnectionState.PROXY_REQUEST_RECEIVED

        if request.cmd == Socks5.structs.REQ_CMD_CONNECT:
            dns = (request.destination_address, request.destination_port)
            destination_socket = self.connection_handler.start_connection(dns)

            logger.debug("Accepting TCP RELAY request, direct client to %s:%d", self.single_socket.get_myip(),
                         self.single_socket.get_myport())

            # Switch to TCP relay mode
            self.connection_handler.switch_to_tcp_relay(self.single_socket, destination_socket)

            response = Socks5.structs.encode_reply(0x05, 0x00, 0x00, Socks5.structs.ADDRESS_TYPE_IPV4, self.single_socket.get_myip(),
                                                   self.single_socket.get_myport())
            self.write(response)
        elif request.cmd == Socks5.structs.REQ_CMD_UDP_ASSOCIATE:
            socket = self.connection_handler.server.create_udp_relay()

            # We use same IP as the single socket, but the port number comes from the newly created UDP listening socket
            ip, port = self.single_socket.get_myip(), socket.getsockname()[1]

            logger.info("Accepting UDP ASSOCIATE request, direct client to %s:%d", ip, port)

            response = Socks5.structs.encode_reply(0x05, 0x00, 0x00, Socks5.structs.ADDRESS_TYPE_IPV4, ip, port)
            self.write(response)

        self.state = ConnectionState.PROXY_REQUEST_ACCEPTED


    def _process_buffer(self):
        """
        Processes the buffer by attempting to messages which are to be expected in the current state
        :return:
        """
        while len(self.buffer) > 0:
            # We are at the initial state, so we expect a handshake request.
            if self.state == ConnectionState.BEFORE_METHOD_REQUEST:
                if not self._try_handshake():
                    break   # Not enough bytes so wait till we got more

            # We are connected so the
            elif self.state == ConnectionState.CONNECTED:
                if not self._try_request():
                    break   # Not enough bytes so wait till we got more


    def write(self, data):
        if self.single_socket is not None:
            self.single_socket.write(data)

    def close(self):
        if self.single_socket is not None:
            self.single_socket.close()
            self.connection_handler.connection_lost(self.single_socket)
            self.single_socket = None

