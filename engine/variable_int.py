class VariableInt:
    @staticmethod
    def pack(buffer: bytearray, i: int, index: int = None):
        # set sign bit if i<0

        if index is None:
            index = len(buffer)

        if index >= len(buffer):
            buffer.extend([0] * (index - (len(buffer) - 1)))

        buffer[index] = (i >> 25) & 0x40

        # if(i<0) i = ~i
        i = i ^ (i >> 31)

        # pack 6bit into dst
        buffer[index] |= i & 0x3F

        i >>= 6  # discard 6 bits

        if i:
            # Set extend bit
            buffer[index] |= 0x80

            while i:
                index += 1
                if index >= len(buffer):
                    buffer.extend([0] * (index - (len(buffer) - 1)))
                # pack 7bit
                buffer[index] = i & 0x7F
                # discard 7 bits
                i >>= 7
                # set extend bit (may branch)
                buffer[index] |= (i != 0) << 7

                if not i:
                    break

        index += 1
        return index

    @staticmethod
    def unpack(index: int, buffer: bytearray):
        sign = (buffer[index] >> 6) & 1

        def check():
            return not (buffer[index] & 0x80)

        out = buffer[index] & 0x3F

        while True:
            if check():
                break
            index += 1
            out |= (buffer[index] & 0x7F) << 6

            if check():
                break
            index += 1
            out |= (buffer[index] & 0x7F) << (6 + 7)

            if check():
                break
            index += 1
            out |= (buffer[index] & 0x7F) << (6 + 7 + 7)

            if check():
                break
            index += 1
            out |= (buffer[index] & 0x7F) << (6 + 7 + 7 + 7)
            break

        index += 1
        out ^= - sign
        return index, out

    @staticmethod
    def decompress(src: bytearray, dst: bytearray):
        srci = 0
        dsti = 0

        while srci < len(src):
            if dsti >= len(dst) / 4:
                return -1
            srci, i = VariableInt.unpack(srci, src)
            dst[dsti] = i
            dsti += 1

        return dsti - len(dst)

    @staticmethod
    def compress(src: bytearray, dst: bytearray):
        size = len(src) / 4

        srci = 0
        dsti = 0
        while size:
            if len(dst) - dsti < 6:
                return -1

            dsti = VariableInt.pack(dst, src[srci], dsti)
            size -= 1
            srci += 1
        return dsti - len(dst)
