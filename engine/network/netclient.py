from .network import *
from .recvunpacker import NetRecvUnpacker
from .netbase import NetBase
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SO_RCVBUF, IPPROTO_IP, IP_TOS


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
