from .variable_int import VariableInt

PACKER_BUFFER_SIZE = 1024 * 2


class Packer:
    def __init__(self):
        self.current_index = 0
        self.buffer = bytearray(PACKER_BUFFER_SIZE)

    def add_int(self, i: int):
        if len(self.buffer) - self.current_index < 6:
            raise BufferError("Not enough space to allocate a variable int.")
        else:
            self.current_index = VariableInt.pack(self.current_index, self.buffer, i)

    def add_str(self, string: str, limit: int=0):
        if len(string) > 0:
            for i, x in enumerate(string):
                if i >= limit != 0:
                    break

                self.buffer[self.current_index] = x.encode()
                self.current_index += 1
                limit -= 1

        # null char at end of str
        self.buffer[self.current_index] = 0
        self.current_index += 1

    def add_raw(self, data: bytes):
        for x in data:
            self.buffer[self.current_index] = x
            self.current_index += 1

    def reset(self):
        self.current_index = 0
        self.buffer = bytearray(PACKER_BUFFER_SIZE)
