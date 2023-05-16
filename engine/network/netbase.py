import sys
import socket

from .network import NetAddr, NetPacketConstruct
from ..huffman import huffman
from .constants import \
    NET_PACKETFLAG_CONTROL, \
    NET_SECURITY_TOKEN_UNSUPPORTED, \
    NET_PACKETFLAG_COMPRESSION, \
    NET_PACKETHEADERSIZE, \
    NET_MAX_PACKETSIZE, \
    NET_PACKETFLAG_CONNLESS, \
    NET_HEADER_EXTENDED, \
    NET_MAX_SEQUENCE, \
    NET_PACKETFLAG_EXTENDED

class NetBase:
    compress = huffman.compress
    decompress = huffman.decompress

    @staticmethod
    def send_packet(_socket: socket.socket, address: NetAddr, packet: NetPacketConstruct, security_token: int):
        if security_token != NET_SECURITY_TOKEN_UNSUPPORTED:
            packet.chunk_data += security_token.to_bytes(4, byteorder=sys.byteorder, signed=True)

        buffer = bytearray(3)
        compressed = NetBase.compress(packet.chunk_data)

        if 0 < len(compressed) < len(packet):
            buffer += compressed
            packet.flags |= NET_PACKETFLAG_COMPRESSION
        else:
            buffer += packet.chunk_data
            packet.flags &= ~NET_PACKETFLAG_COMPRESSION

        if len(buffer) >= 0:
            buffer[0] = ((packet.flags << 4) & 0xf0) | ((packet.ack >> 8) & 0xf)
            buffer[1] = packet.ack & 0xff
            buffer[2] = packet.num_chunks
            _socket.sendto(buffer, (address.ip, address.port))

    @staticmethod
    def send_packet_conless(_socket: socket.socket, address: NetAddr,
                            data: bytearray, extended: bool, data_extra: bytearray):
        buffer = bytearray()
        data_offset = 6

        if not extended:
            for x in range(data_offset):
                buffer.append(0xff)
        else:
            buffer += NET_HEADER_EXTENDED
            buffer += data_extra

        buffer += data
        _socket.sendto(buffer, (address.ip, address.port))

    @staticmethod
    def send_control_msg(_socket: socket.socket, address: NetAddr, ack: int,
                         control_msg: int, extra: bytearray, security_token: int):
        print("called")
        construct = NetPacketConstruct()
        construct.flags = NET_PACKETFLAG_CONTROL
        construct.ack = ack
        construct.num_chunks = 0
        construct.chunk_data = bytearray()
        construct.chunk_data += control_msg.to_bytes(4, byteorder=sys.byteorder)
        construct.chunk_data += extra
        NetBase.send_packet(_socket, address, construct, security_token)

    @staticmethod
    def is_seq_in_backroom(seq: int, ack: int):
        bottom = ack - NET_MAX_SEQUENCE / 2
        if bottom < 0:
            if seq <= ack:
                return True
            if seq >= bottom + NET_MAX_SEQUENCE:
                return True
        else:
            if bottom <= seq <= ack:
                return True
        return False

    @staticmethod
    def unpack_packet(buffer: bytearray, packet: NetPacketConstruct):
        if len(buffer) < NET_PACKETHEADERSIZE or len(buffer) > NET_MAX_PACKETSIZE:
            return False

        packet.flags = buffer[0] >> 4
        packet.ack = (buffer[0] & 0xf) << 8 or buffer[1]
        packet.num_chunks = buffer[2]
        data_size = len(buffer) - NET_PACKETHEADERSIZE

        if packet.flags & NET_PACKETFLAG_CONNLESS:
            data_offset = 6
            if data_size < data_offset:
                return False

            packet.flags = NET_PACKETFLAG_CONNLESS
            packet.ack = 0
            packet.num_chunks = 0
            packet.chunk_data = buffer[data_offset::]

            if buffer[0:len(NET_HEADER_EXTENDED)] == NET_HEADER_EXTENDED:
                packet.flags |= NET_PACKETFLAG_EXTENDED
                packet.extra_data = buffer[len(NET_HEADER_EXTENDED):len(NET_HEADER_EXTENDED) + 4]
        else:
            if packet.flags & NET_PACKETFLAG_COMPRESSION:
                if packet.flags & NET_PACKETFLAG_CONTROL:
                    return False

                packet.chunk_data = huffman.decompress(buffer, 3)
            else:
                packet.chunk_data = buffer[3::]

        if len(packet) < 0:
            print("error during packet decoding")
            return False

        return True
