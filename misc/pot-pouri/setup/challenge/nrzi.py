class NRZI:
    def __init__(self, initial_level: int = 1):
        self.initial_level = initial_level
        self.level = initial_level
        self.bits = ''

    def reset(self):
        self.level = self.initial_level
        self.bits = ''

    def encode(self, data: str) -> str:
        self.reset()

        for char in data:
            byte_bits = format(ord(char), '08b')

            for bit in byte_bits:
                if bit == '1':
                    self.level ^= 1
                self.bits += str(self.level)

        return self.bits
