class Hamming:
    def split(self, bits, size):
        return [int(bits[i:i + size], 2) for i in range(0, len(bits), size)]

    def str_to_bits(self, str):
        return "".join("{0:08b}".format(ord(x), 'b') for x in str)

    def int_to_bits(self, x, bit_size):
        str_format = "{0:0" + str(bit_size) + "b}"
        return str_format.format(x, 'b')

    def extract_bit(self, byte, pos):
        return (byte >> pos) & 0x01

    def merge_bits(self, bit_list):
        encoded = 0
        for i, enc in enumerate(bit_list[::-1]):
            encoded |= (enc << i)
        return encoded

    def encode(self, data):
        data = self.str_to_bits(data)
        blocks = self.split(data, 4)
        encoded_block_list = []

        for block in blocks:
            d = [self.extract_bit(block, i) for i in range(4)]

            h0 = (d[3] + d[2] + d[0]) % 2
            h1 = (d[3] + d[1] + d[0]) % 2
            h2 = (d[2] + d[1] + d[0]) % 2

            encoded_list = [h0, h1, d[3], h2, d[2], d[1], d[0]]
            encoded_block = self.merge_bits(encoded_list)
            encoded_block_list.append(encoded_block)

        return "".join(self.int_to_bits(block, 7) for block in encoded_block_list)
