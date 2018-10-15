from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SO_RCVBUF, IPPROTO_IP, IP_TOS
from .constants import *
from ..huffman import huffman
from ..system import time_freq, time_get, str_sanitize_strong
from typing import Deque
from collections import deque
import sys
import time

SECURITY_TOKEN_MAGIC = bytearray("TKEN".encode())


def to_security_token(data: bytearray):
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)


class NetStats:
    def __init__(self):
        self.sent_packets: int = None
        self.sent_bytes: int = None
        self.recv_packets: int = None
        self.recv_bytes: int = None


class NetAddr:
    def __init__(self):
        self.type = 0
        self.ip = bytearray(16)
        self.port = 0

    def get_tuple(self):
        return self.ip, self.port

    def __eq__(self, other):
        return self.ip == other.ip and self.port == other.port


class NetChunk:
    """
    A packet
    If the client id is -1 it's a stateless packet
    If the client id is 0 on client means the server
    """

    def __init__(self):
        self.client_id: int = None
        self.address: NetAddr = None
        self.data: bytearray = None
        self.flags: int = None
        self.extra_data: None = None

    def __len__(self):
        return len(self.data)


class NetChunkHeader:
    def __init__(self):
        self.flags: int = None
        self.size: int = None
        self.sequence: int = None

    def pack(self, data: bytearray):
        """Returns the new index"""
        index = len(data)
        data.extend([0] * 2)

        data[index] = ((self.flags & 3) << 6) | ((self.size >> 4) & 0x3f)
        data[index + 1] = self.size & 0xf

        if self.flags & NET_CHUNKFLAG_VITAL:
            data[index + 1] |= (self.sequence >> 2) & 0xf0
            data.extend([0])
            data[index + 2] = self.sequence & 0xff
            return index + 3
        return index + 2

    def unpack(self, index: int, data: bytearray):
        self.flags = (data[index] >> 6) & 3
        self.size = ((data[index] & 0x3f) << 4) | (data[index + 1] & 0xf)
        self.sequence = -1

        if self.flags & NET_CHUNKFLAG_VITAL:
            self.sequence = ((data[index + 1] & 0xf0) << 2) | data[index + 2]
            return index + 3
        return index + 2


class NetChunkResend:
    def __init__(self):
        self.flags: int = None
        self.size: int = None
        self.data: bytearray = None
        self.sequence: int = None
        self.last_send_time: int = None
        self.first_send_time: int = None


class NetPacketConstruct:
    def __init__(self, ):
        self.flags: int = None
        self.ack: int = None
        self.num_chunks: int = 0
        # Size NET_MAX_PAYLOAD
        self.chunk_data: bytearray = None
        self.chunk_data_index: int = None
        # Size 4
        self.extra_data: bytearray = None

    def __len__(self):
        return len(self.chunk_data)


class NetConnection:
    def __init__(self):
        self.sequence: int = None
        self.ack: int = None
        self.peer_ack: int = None
        self.state: int = None  # unsigned
        self.token: int = None
        self.security_token: int = None
        self.remote_closed: int = None
        self.block_close_msg: int = None
        self.unknown_seq: bool = None

        self.buffer: Deque[NetChunkResend] = None

        self.last_update_time: int = None
        self.last_recv_time: int = None
        self.last_send_time: int = None

        self.error_string: str = None
        self.construct: NetPacketConstruct = None

        self.peer_address: NetAddr = None
        self.socket: socket = None
        self.stats: NetStats = None

        self.timeout_protected: bool = None
        self.timeout_situation: bool = None

    def signal_resend(self):
        raise NotImplementedError

    def reset_stats(self):
        self.stats = None
        self.last_update_time = 0
        self.peer_address = None

    def ack_chunks(self, ack: int):
        while True:
            if len(self.buffer) == 0:
                break

            resend = self.buffer[0]

            if NetBase.is_seq_in_backroom(resend.sequence, ack):
                self.buffer.popleft()
            else:
                break

    def flush(self):
        num_chunks = self.construct.num_chunks

        if not num_chunks and not self.construct.flags:
            return 0

        self.construct.ack = self.ack
        NetBase.send_packet(self.socket, self.peer_address, self.construct, self.security_token)
        self.last_send_time = time_get()
        self.construct = None
        return num_chunks

    def queue_chunks_ex(self, flags: int, data: bytearray, sequence: int):
        if self.state == NET_CONNSTATE_OFFLINE or self.state == NET_CONNSTATE_ERROR:
            return False

        if len(self.construct) + len(data) + NET_MAX_CHUNKHEADERSIZE > NET_MAX_PAYLOAD - 4:
            self.flush()

        header = NetChunkHeader()
        header.flags = flags
        header.size = len(data)
        header.sequence = sequence
        header.pack(self.construct.chunk_data)
        self.construct.chunk_data += data

        self.construct.num_chunks += 1

        if (flags & NET_CHUNKFLAG_VITAL) and not (flags & NET_CHUNKFLAG_RESEND):
            resend = NetChunkResend()
            resend.sequence = sequence
            resend.flags = flags
            resend.size = len(data)
            resend.data = data
            resend.first_send_time = time_get()
            resend.last_send_time = resend.first_send_time
            self.buffer.append(resend)

    def send_control(self, control_msg: int, extra: bytearray):
        self.last_send_time = time_get()
        NetBase.send_control_msg(self.socket, self.peer_address, self.ack, control_msg, extra, self.security_token)

    def resend_chunk(self, resend: NetChunkResend):
        self.queue_chunks_ex(resend.flags | NET_CHUNKFLAG_RESEND, resend.data, resend.sequence)
        resend.last_send_time = time_get()

    def queue_chunk(self, flags: int, data: bytearray):
        if flags & NET_CHUNKFLAG_VITAL:
            self.sequence = (self.sequence + 1) % NET_MAX_SEQUENCE
        return self.queue_chunks_ex(flags, data, self.sequence)

    def resend(self):
        for x in self.buffer:
            self.resend_chunk(x)

    def reset(self, rejoin=False):
        self.sequence = 0
        self.ack = 0
        self.peer_ack = 0
        self.remote_closed = 0

        if not rejoin:
            self.timeout_protected = False
            self.timeout_situation = False

            self.state = NET_CONNSTATE_OFFLINE
            self.token = -1
            self.security_token = NET_SECURITY_TOKEN_UNKNOWN

        self.last_send_time = 0
        self.last_recv_time = 0

        self.unknown_seq = False
        self.buffer = deque([], maxlen=NET_CONN_BUFFERSIZE)
        self.construct = NetPacketConstruct()

    def connect(self, addr: NetAddr):
        if self.state != NET_CONNSTATE_OFFLINE:
            return False

        self.reset()
        self.peer_address = addr
        self.error_string = ""
        self.state = NET_CONNSTATE_CONNECT
        self.send_control(NET_CTRLMSG_CONNECT, SECURITY_TOKEN_MAGIC)
        return True

    def disconnect(self, reason: str = ""):
        if self.state == NET_CONNSTATE_OFFLINE:
            return

        if self.remote_closed == 0:
            if not self.timeout_situation:
                if len(reason) > 0:
                    self.send_control(NET_CTRLMSG_CLOSE, bytearray(reason.encode()))
                else:
                    self.send_control(NET_CTRLMSG_CLOSE, bytearray())

            if reason != self.error_string:
                self.error_string = reason
        self.reset()

    def init(self, _socket: socket, block_close_msg: bool):
        self.reset()
        self.reset_stats()
        self.socket = _socket
        self.block_close_msg = block_close_msg
        self.error_string = ""

    def update(self):
        now = time_get()
        # TODO: g_Config.m_ConnTimeoutProtection is missing here, it muls time_freq()
        if self.state == NET_CONNSTATE_ERROR and self.timeout_situation and (now - self.last_recv_time) > time_freq():
            self.timeout_situation = False
            self.error_string = "Timeout Protection over"

        if self.state == NET_CONNSTATE_OFFLINE or self.state == NET_CONNSTATE_ERROR:
            return False

        self.timeout_situation = False

        if self.state != NET_CONNSTATE_OFFLINE and self.state != NET_CONNSTATE_OFFLINE \
                and (now - self.last_recv_time) > time_freq():
            self.state = NET_CONNSTATE_ERROR
            self.error_string = "Timeout"
            self.timeout_situation = True

        # Fix resends
        # TODO: not sure about this part
        if len(self.buffer) > 0:
            # TODO: g_Config.m_ConnTimeout instead of 30
            if now - self.buffer[0].first_send_time > time_freq() * 30:
                self.state = NET_CONNSTATE_ERROR
                self.error_string = "Too weak connection (not acked for 30 seconds)"
                self.timeout_situation = True
            elif now - self.buffer[0].last_send_time > time_freq():
                self.resend_chunk(self.buffer[0])

        # send keep alives if nothing has happened for 250ms
        if self.state == NET_CONNSTATE_ONLINE:
            if time_get() - self.last_send_time > time_get() / 2:
                self.flush()
                # TODO debug log

            if time_get() - self.last_send_time > time_freq():
                self.send_control(NET_CTRLMSG_KEEPALIVE, bytearray())
        elif self.state == NET_CONNSTATE_CONNECT:
            # send a new connect every 500ms
            if time_get() - self.last_send_time > time_freq() / 2:
                self.send_control(NET_CTRLMSG_CONNECT, SECURITY_TOKEN_MAGIC)
        elif self.state == NET_CONNSTATE_PENDING:
            # send a new connect/accept every 500ms
            if time_get() - self.last_send_time > time_freq() / 2:
                self.send_control(NET_CTRLMSG_CONNECTACCEPT, SECURITY_TOKEN_MAGIC)

        return 0

    def feed(self, packet: NetPacketConstruct, addr: NetAddr, security_token: int = NET_SECURITY_TOKEN_UNSUPPORTED):
        if self.state != NET_CONNSTATE_OFFLINE and security_token != NET_SECURITY_TOKEN_UNKNOWN \
                and security_token != NET_SECURITY_TOKEN_UNSUPPORTED:
            # supposed to have a valid token in this packet, check it
            # TODO: is this correct? header size?
            if len(packet) < 4:
                return False

            if security_token != to_security_token(packet.chunk_data[-4::]):
                print("Security token not valid, maybe remove this print?")
                print("Expected ", security_token, " got: ", to_security_token(packet.chunk_data[-4::]))
                return False

        # check if actual ack value is valid(own sequence..latest peer ack)
        if self.sequence >= self.peer_ack:
            if packet.ack < self.peer_ack or packet.ack > self.sequence:
                return False
        else:
            if self.peer_ack > packet.ack > self.sequence:
                return False

        self.peer_ack = packet.ack

        now = time_get()

        if packet.flags & NET_PACKETFLAG_RESEND:
            self.resend()

        if packet.flags & NET_PACKETFLAG_CONTROL:
            ctrl_msg = packet.chunk_data[0]

            if ctrl_msg == NET_CTRLMSG_CLOSE:
                if self.peer_address == addr:
                    self.state = NET_CONNSTATE_ERROR
                    self.remote_closed = 1

                    text = ""

                    if len(packet) > 1:
                        if len(packet) < 128:
                            text = packet.chunk_data[1::].decode()
                        else:
                            text = packet.chunk_data[1:128].decode()
                        text = str_sanitize_strong(text)

                    if not self.block_close_msg:
                        self.error_string = text

                    print("Closed, reason: ", text)
                return False
            else:
                if self.state == NET_CONNSTATE_OFFLINE:
                    if ctrl_msg == NET_CTRLMSG_CONNECT:
                        address = addr
                        address.port = 0
                        self.peer_address.port = 0

                        if address == self.peer_address and time_get() - self.last_update_time < time_get() * 3:
                            return False

                        # send response and init connection
                        self.reset()
                        self.state = NET_CONNSTATE_PENDING
                        self.peer_address = addr
                        self.error_string = ""
                        self.last_send_time = now
                        self.last_recv_time = now
                        self.last_update_time = now
                        if self.security_token == NET_SECURITY_TOKEN_UNKNOWN and len(packet) > 1 + 4 + 4 \
                                and packet.chunk_data[1:1 + 4] != SECURITY_TOKEN_MAGIC:
                            self.security_token = security_token
                            print("generated token: ", self.security_token)
                        else:
                            self.security_token = NET_SECURITY_TOKEN_UNSUPPORTED

                        self.send_control(NET_CTRLMSG_CONNECTACCEPT, SECURITY_TOKEN_MAGIC)
                        print("got connection, sending connect+accept")
                elif self.state == NET_CONNSTATE_CONNECT:
                    if ctrl_msg == NET_CTRLMSG_CONNECTACCEPT:
                        if self.security_token == NET_SECURITY_TOKEN_UNKNOWN and len(packet) > 1 + 4 + 4 \
                                and packet.chunk_data[1:1 + 4] != SECURITY_TOKEN_MAGIC:
                            self.security_token = to_security_token(packet.chunk_data[1:1 + 4])
                            print("got token ", self.security_token)
                        else:
                            self.security_token = NET_SECURITY_TOKEN_UNSUPPORTED
                            print("token not supported by server")
                        self.last_recv_time = now
                        self.send_control(NET_CTRLMSG_ACCEPT, bytearray())
                        self.state = NET_CONNSTATE_ONLINE
                        print("got connect+accept, sending accept. connection online")

        else:
            if self.state == NET_CONNSTATE_PENDING:
                self.last_recv_time = now
                self.state = NET_CONNSTATE_ONLINE
                print("connecting online")

        if self.state == NET_CONNSTATE_ONLINE:
            self.last_recv_time = now
            self.ack_chunks(packet.ack)

        return True


class NetBase:
    compress = huffman.compress
    decompress = huffman.decompress

    @staticmethod
    def send_packet(_socket: socket, address: NetAddr, packet: NetPacketConstruct, security_token: int):
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
    def send_packet_conless(_socket: socket, address: NetAddr,
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
    def send_control_msg(_socket: socket, address: NetAddr, ack: int,
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


class NetRecvUnpacker:
    def __init__(self):
        self.valid: bool = None
        self.address: NetAddr = None
        self.connection: NetConnection = None
        self.current_cunk: int = None
        self.client_id: int = None
        self.data: NetPacketConstruct = None
        self.buffer = bytearray(NET_MAX_PACKETSIZE)
        self.clear()

    def clear(self):
        self.valid = False

    def start(self, address: NetAddr, conn: NetConnection, client_id: int):
        self.address = address
        self.connection = conn
        self.client_id = client_id
        self.current_cunk = 0
        self.valid = True

    def fetch_chunk(self, chunk: NetChunk):
        header: NetChunkHeader = NetChunkHeader()
        end = len(self.data)

        while True:
            if not self.valid or self.current_cunk >= self.data.num_chunks:
                self.clear()
                return False

            for x in range(self.current_cunk):
                self.data.chunk_data_index = header.unpack(self.data.chunk_data_index, self.data.chunk_data)
                self.data.chunk_data_index += header.size

            self.data.chunk_data_index = header.unpack(self.data.chunk_data_index, self.data.chunk_data)
            self.current_cunk += 1

            if self.data.chunk_data_index + header.size > end:
                self.clear()
                return False

            if self.connection and (header.flags & NET_CHUNKFLAG_VITAL):
                # anti spoof: ignore unknown sequence
                if header.sequence == ((self.connection.ack + 1) % NET_MAX_SEQUENCE or self.connection.unknown_seq):
                    self.connection.unknown_seq = False
                    self.connection.ack = header.sequence
                else:
                    if NetBase.is_seq_in_backroom(header.sequence, self.connection.ack):
                        continue

                    self.connection.signal_resend()
                    continue

            chunk.client_id = self.client_id
            chunk.address = self.address
            chunk.flags = header.flags
            chunk.data = self.data
            return True


class NetClient:

    def __init__(self):
        self.connection: NetConnection = NetConnection()
        self.recv_unpacker: NetRecvUnpacker = NetRecvUnpacker()
        self.socket: socket = None

    def open(self):
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 65536)
        self.socket.setsockopt(IPPROTO_IP, IP_TOS, 0x10)
        self.socket.setblocking(False)
        self.connection = NetConnection()
        self.connection.init(self.socket, False)

    def close(self):
        # on tw source it says
        # to_do: implement me
        self.socket.close()

    def disconnect(self, reason: str):
        return self.connection.disconnect(reason)

    def update(self):
        self.connection.update()
        if self.connection.state == NET_CONNSTATE_ERROR:
            self.disconnect(self.connection.error_string)

    def connect(self, addr: NetAddr):
        self.connection.connect(addr)

    def reset_err_string(self):
        self.connection.error_string = ""

    def recv(self, chunk: NetChunk):
        while True:
            if self.recv_unpacker.fetch_chunk(chunk):
                return 1

            addr = NetAddr()
            buffer, address = self.socket.recvfrom(NET_MAX_PACKETSIZE)
            addr.ip = bytearray(address[0].encode())
            addr.port = address[1]

            if len(buffer) < 0:
                break

            if NetBase.unpack_packet(self.recv_unpacker.buffer, self.recv_unpacker.data):
                if self.recv_unpacker.data.flags & NET_PACKETFLAG_CONNLESS:
                    chunk.flags = NETSENDFLAG_CONNLESS
                    chunk.client_id = -1
                    chunk.address = addr
                    chunk.data = self.recv_unpacker.data.chunk_data

                    if self.recv_unpacker.data.flags & NET_PACKETFLAG_EXTENDED:
                        chunk.flags |= NETSENDFLAG_EXTENDED
                        chunk.extra_data = self.recv_unpacker.data.extra_data
                    return True
                else:
                    if self.connection.state != NET_CONNSTATE_OFFLINE and self.connection.state != NET_CONNSTATE_ERROR \
                            and self.connection.peer_address == addr \
                            and self.connection.feed(self.recv_unpacker.data, addr):
                        self.recv_unpacker.start(addr, self.connection, 0)
        return True

    def send(self, chunk: NetChunk):
        if len(chunk) >= NET_MAX_PAYLOAD:
            print("payload chunk too big, dropping chunk: ", len(chunk))
            return False

        if chunk.flags & NETSENDFLAG_CONNLESS:
            NetBase.send_packet_conless(self.socket, chunk.address, chunk.data,
                                        chunk.flags & NETSENDFLAG_EXTENDED, chunk.extra_data)
        else:
            flags = 0
            assert chunk.client_id == 0, "errornous client id"

            if chunk.flags & NETSENDFLAG_VITAL:
                flags = NET_CHUNKFLAG_VITAL

            self.connection.queue_chunk(flags, chunk.data)

            if chunk.flags & NETSENDFLAG_FLUSH:
                self.connection.flush()
        return True

    def state(self):
        if self.connection.state == NET_CONNSTATE_ONLINE:
            return NETSTATE_ONLINE
        if self.connection.state == NET_CONNSTATE_OFFLINE:
            return NETSTATE_OFFLINE
        return NETSTATE_CONNECTING

    def flush(self):
        return self.connection.flush()

    def got_problems(self):
        return time_get() - self.connection.last_recv_time > time_freq()

    def security_token_unknown(self):
        return self.connection.security_token == NET_SECURITY_TOKEN_UNKNOWN
