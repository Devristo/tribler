import logging
from Tribler.Core.Libtorrent.LibtorrentMgr import LibtorrentMgr
from Tribler.community.anontunnel.Socks5 import conversion
from Tribler.community.anontunnel.community import TunnelObserver

logger = logging.getLogger()


class Socks5Session(TunnelObserver):
    """
    A SOCKS5 session, composed by a TCP connection, an UDP proxy port and a
    list of circuits where data can be tunneled over

    @param Socks5Connection connection: the Socks5Connection
    @param RawServer raw_server: The raw server, used to create and listen on
    UDP-sockets
    @param list[Tribler.community.anontunnel.community.Circuit] circuits: the
    circuits allocated to this session
    """

    def __init__(self, raw_server, connection, circuits):
        TunnelObserver.__init__(self)
        self.raw_server = raw_server
        self.connection = connection
        self.circuits = circuits
        ''' :type : list[Circuit] '''
        self.destinations = {}
        ''' :type: dict[(str, int), Circuit] '''
        self.connection.udp_associate = self._udp_associate
        self.remote_udp_address = None
        self._udp_socket = None

        self._select_index = -1

    def _udp_associate(self):
        self._udp_socket = self.raw_server.create_udpsocket(0, "0.0.0.0")
        self.raw_server.start_listening_udp(self._udp_socket, self)
        return self._udp_socket

    def close_session(self, reason='unspecified'):
        """
        Closes the session and the linked TCP connection
        @param str reason: the reason why the session should be closed
        """
        logger.error("Closing session, reason = {0}".format(reason))
        LibtorrentMgr.getInstance().ltsession_anon.pause()

        self.connection.close()

    def on_break_circuit(self, circuit):
        if circuit in self.circuits:
            logger.error("A circuit has died, to enforce 3-way swift handshake"
                         " we are signalling swift by closing TCP connection")
            self.close_session()

    def _select(self, destination):

        if not destination in self.destinations:
            self._select_index = (self._select_index + 1) % len(self.circuits)
            self.destinations[destination] = self.circuits[self._select_index]

            logger.error("SELECT circuit {0} for {1}".format(
                self.destinations[destination].circuit_id,
                destination
            ))

        return self.destinations[destination]

    def data_came_in(self, packets):
        for source_address, packet in packets:
            if self.remote_udp_address and \
                    self.remote_udp_address != source_address:
                self.close_session('invalid source_address!')
                return

            self.remote_udp_address = source_address

            request = conversion.decode_udp_packet(packet)

            circuit = self._select(request.destination)
            logger.debug("Relaying UDP packets from {0} to {1}".format(
                         self.remote_udp_address, request.destination))

            circuit.tunnel_data(request.destination, request.payload)

    def on_incoming_from_tunnel(self, community, circuit, origin, data):
        self.destinations[origin] = circuit

        socks5_udp = conversion.encode_udp_packet(
            0, 0, conversion.ADDRESS_TYPE_IPV4, origin[0], origin[1], data)

        bytes_written = self._udp_socket.sendto(socks5_udp,
                                                self.remote_udp_address)
        if bytes_written < len(socks5_udp):
            logger.error("Packet drop on return!")

        logger.info("Returning UDP packets from %s to %s using proxy port %d",
                    origin, self.remote_udp_address,
                    self._udp_socket.getsockname()[1])
