from .variable_int import VariableInt
from .system import str_sanitize, str_sanitize_cc
import re
PACKER_BUFFER_SIZE = 1024 * 2


class Unpacker:
    SANITIZE = 1
    SANITIZE_CC = 2
    SKIP_START_WHITESPACES = 4

    def __init__(self):
        self.current_index = 0
        self.buffer = bytearray(PACKER_BUFFER_SIZE)

    def reset(self, buffer: bytearray):
        self.current_index = 0
        self.buffer = buffer

    def get_int(self):
        self.current_index, i = VariableInt.unpack(self.current_index, self.buffer)
        return i

    def get_string(self, sanitize_type: int):

        string = ""

        while True:
            x = self.buffer[self.current_index]

            if x == 0:
                self.current_index += 1
                break
            else:
                string += chr(x)
                self.current_index += 1

        if sanitize_type & self.SANITIZE:
            string = str_sanitize(string)
        elif sanitize_type & self.SANITIZE_CC:
            string = str_sanitize_cc(string)

        if sanitize_type & self.SKIP_START_WHITESPACES:
            return re.sub(r"[ ]+$", '', string)
        else:
            return string

    def get_raw(self, size: int):
        if size < 0 or self.current_index + size > len(self.buffer):
            raise ValueError("Size can't be less than 0 or bigger than the buffer size.")

        data = self.buffer[self.current_index:self.current_index + size]
        self.current_index += size
        return data
