class Manchester:
    def __init__(self):
        self.bits = ''

    def reset(self):
        self.bits = ''

    def encode(self, data: str) -> str:
        self.reset()

        for char in data:
            byte_bits = format(ord(char), '08b')

            for bit in byte_bits:
                if bit == '1':
                    self.bits += '10'
                else:
                    self.bits += '01'

        return self.bits
