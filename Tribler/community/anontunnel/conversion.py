import struct
from Tribler.Core.Utilities.encoding import encode, decode

from Tribler.dispersy.conversion import BinaryConversion
from Tribler.community.anontunnel.payload import *
from Tribler.community.anontunnel.globals import *

class ProxyConversion(BinaryConversion):
    def __init__(self, community):
        super(ProxyConversion, self).__init__(community, "\x01")

        self.define_meta_message(
            chr(1),
            community.get_meta_message(u"stats")
            , self._encode_stats
            , self._decode_stats
        )

    @staticmethod
    def _encode_stats(message):
        return encode(message.payload.stats),

    @staticmethod
    def _decode_stats(placeholder, offset, data):
        offset, stats = decode(data, offset)

        return offset, placeholder.meta.payload.implement(stats)

class CustomProxyConversion():
    
    def __init__(self, prefix):
        self.prefix = prefix
        
        self.encode_functions = {}
        self.decode_functions = {}
        
        self.encode_functions[MESSAGE_CREATE] = lambda message: ''
        self.decode_functions[MESSAGE_CREATE] = lambda buffer, offset: CreateMessage()

        self.encode_functions[MESSAGE_CREATED] = lambda message: ''
        self.decode_functions[MESSAGE_CREATED] = lambda buffer, offset: CreatedMessage()
        
        self.encode_functions[MESSAGE_EXTEND] = self.__encode_extend
        self.decode_functions[MESSAGE_EXTEND] = self.__decode_extend

        self.encode_functions[MESSAGE_EXTENDED] = self.__encode_extended
        self.decode_functions[MESSAGE_EXTENDED] = self.__decode_extended

        self.encode_functions[MESSAGE_DATA] = self.__encode_data
        self.decode_functions[MESSAGE_DATA] = self.__decode_data
        
        self.encode_functions[MESSAGE_BREAK] = lambda message: ''
        self.decode_functions[MESSAGE_BREAK] = lambda buffer, offset: BreakMessage()
        
        self.encode_functions[MESSAGE_PING] = lambda message: ''
        self.decode_functions[MESSAGE_PING] = lambda buffer, offset: PingMessage()
        
        self.encode_functions[MESSAGE_PONG] = lambda message: ''
        self.decode_functions[MESSAGE_PONG] = lambda buffer, offset: PongMessage()
        
        self.encode_functions[MESSAGE_PUNCTURE] = self.__encode_puncture
        self.decode_functions[MESSAGE_PUNCTURE] = self.__decode_puncture
        
    
    def encode(self, circuit_id, type, message):
        return self.prefix + struct.pack("!L", circuit_id) + type + self.encode_functions[type](message)
    
    def decode(self, data, offset=0):
        message_type = data[offset]
        return message_type, self.decode_functions[message_type](data, offset+1)

    def get_circuit_and_data(self, buffer, offset=0):
        offset += len(self.prefix)
        
        circuit_id, = struct.unpack_from("!L", buffer, offset)
        offset += 4

        return circuit_id, buffer[offset:]

    def get_type(self, data):
        return data[0]
    
    def add_circuit(self, data, new_id):
        return struct.pack("!L", new_id) + data

    def __encode_extend(self, extend_message):
        host = extend_message.host if extend_message.host else ''
        port = extend_message.port if extend_message.port else 0
    
        data = struct.pack("!LL", len(host), port) + host
        return data

    def __decode_extend(self, buffer, offset=0):
        if len(buffer) < offset + 8:
            raise ValueError("Cannot unpack HostLength/Port, insufficient packet size")
        host_length, port = struct.unpack_from("!LL", buffer, offset)
        offset += 8
    
        if len(buffer) < offset + host_length:
            raise ValueError("Cannot unpack Host, insufficient packet size")
        host = buffer[offset:offset + host_length]
        offset += host_length
    
        extended_with = (host, port) if host and port else None
        return ExtendMessage(extended_with)

    def __encode_extended(self, extended_with_message):
        data = struct.pack("!LL", len(extended_with_message.host), extended_with_message.port) + extended_with_message.host
        return data

    def __decode_extended(self, buffer, offset=0):
        if len(buffer) < offset + 8:
            raise ValueError("Cannot unpack HostLength/Port, insufficient packet size")
        host_length, port = struct.unpack_from("!LL", buffer, offset)
        offset += 8
    
        if len(buffer) < offset + host_length:
            raise ValueError("Cannot unpack Host, insufficient packet size")
        host = buffer[offset:offset + host_length]
        offset += host_length
    
        extended_with = (host, port)
    
        return ExtendedWithMessage(extended_with)

    def __encode_data(self, data_message):
        if data_message.destination is None:
            (host, port) = ("0.0.0.0", 0)
        else:
            (host, port) = data_message.destination
    
        if data_message.origin is None:
            origin = ("0.0.0.0", 0)
        else:
            origin = data_message.origin
    
        return struct.pack("!LLLLL", len(host), port, len(origin[0]), origin[1],
                        len(data_message.data)) \
            + host                              \
            + origin[0]                         \
            + data_message.data

    def __decode_data(self, buffer, offset=0):
        host_length, port, origin_host_length, origin_port, payload_length = struct.unpack_from("!LLLLL", buffer, offset)
        offset += 20
    
        if len(buffer) < offset + host_length:
                raise ValueError("Cannot unpack Host, insufficient packet size")
        host = buffer[offset:offset + host_length]
        offset += host_length
    
        destination = (host, port)
    
        if len(buffer) < offset + origin_host_length:
            raise ValueError("Cannot unpack Origin Host, insufficient packet size")
        origin_host = buffer[offset:offset + origin_host_length]
        offset += origin_host_length
    
        origin = (origin_host, origin_port)
    
        if origin == ("0.0.0.0", 0):
            origin = None
    
        if payload_length == 0:
            payload = None
        else:
            if len(buffer) < offset + payload_length:
                raise ValueError("Cannot unpack Data, insufficient packet size")
            payload = buffer[offset:offset + payload_length]
            offset += payload_length

        return DataMessage(destination, payload, origin)

    #why are we using a custom punture-req message?
    def __encode_puncture(self, puncture_message):
        return struct.pack("!LL", len(puncture_message.sock_addr[0]), puncture_message.sock_addr[1]) + puncture_message.sock_addr[0]

    def __decode_puncture(self, buffer, offset=0):
        host_length, port = struct.unpack_from("!LL", buffer, offset)
        offset += 8
    
        if len(buffer) < offset + host_length:
                raise ValueError("Cannot unpack Host, insufficient packet size")
        host = buffer[offset:offset + host_length]
        offset += host_length
    
        destination = (host, port)
    
        return PunctureMessage(destination)