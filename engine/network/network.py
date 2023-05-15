from socket import socket
from .constants import *
from ..system import time_freq, time_get, str_sanitize_strong
from typing import Deque
from collections import deque

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
        self.flags: int = 0
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
        self.flags: int = 0
        self.ack: int = None
        self.num_chunks: int = 0
        # Size NET_MAX_PAYLOAD
        self.chunk_data: bytearray = bytearray()
        self.chunk_data_index: int = 0
        # Size 4
        self.extra_data: bytearray = bytearray()

    def __len__(self):
        return len(self.chunk_data)


