class UART:
    def __init__(self, data_bits=8, parity=False):
        self.data_bits = data_bits
        self.parity = parity
        self.bits = ''

    def calculate_parity(self, data_bits: str) -> bool:
        ones = sum(int(bit) for bit in data_bits)
        return ones % 2 == 0

    def update_bits(self, bit: int):
        self.bits += str(bit)

    def reset(self):
        self.bits = ''

    def encode(self, data: str) -> str:
        self.reset()
        for char in data:
            self.update_bits(0)

            bin_str = format(ord(char), f'0{self.data_bits}b')[::-1]

            for bit in bin_str:
                self.update_bits(int(bit))

            if self.parity:
                p = 0 if self.calculate_parity(bin_str) else 1
                self.update_bits(p)

            self.update_bits(1)

        return self.bits


class RS232(UART):
    def __init__(self, data_bits=8, parity=False, stop_bits=1):
        super().__init__(data_bits, parity)
        self.stop_bits = stop_bits

    def encode(self, data: str) -> str:
        self.reset()
        for char in data:
            self.update_bits(0)

            bin_str = format(ord(char), f'0{self.data_bits}b')[::-1]

            for bit in bin_str:
                self.update_bits(int(bit))

            if self.parity:
                p = 0 if self.calculate_parity(bin_str) else 1
                self.update_bits(p)

            for _ in range(self.stop_bits):
                self.update_bits(1)

        return self.bits
