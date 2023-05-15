from .variable_int import VariableInt
from .network.constants import NET_MAX_PAYLOAD

class Packer:
    def __init__(self):
        self.current_index = 0
        self.buffer = bytearray()

    def add_int(self, i: int):
        if NET_MAX_PAYLOAD - self.current_index < 6:
            raise BufferError("Not enough space to allocate a variable int.")
        else:
            self.current_index = VariableInt.pack(self.buffer, i, self.current_index)

    def add_str(self, string: str, limit: int=0):
        if len(string) > 0:
            i = 0
            for b in string.encode():
                if i >= limit != 0:
                    break
                self.buffer.append(b)
                self.current_index += 1
                limit -= 1

        # null char at end of str
        self.buffer.append(0)
        self.current_index += 1

    def add_raw(self, data: bytes):
        for x in data:
            self.buffer[self.current_index] = x
            self.current_index += 1

    def reset(self):
        self.current_index = 0
        self.buffer = bytearray()
