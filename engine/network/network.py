from socket import socket
from .constants import *
from ..system import time_freq, time_get, str_sanitize_strong
from typing import Deque
from collections import deque
from .netbase import NetBase

SECURITY_TOKEN_MAGIC = bytearray("TKEN".encode())
SHA256_DIGEST_LENGTH = 256 / 8


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
