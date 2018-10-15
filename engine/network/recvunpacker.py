from .network import *
from .netbase import NetBase


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
