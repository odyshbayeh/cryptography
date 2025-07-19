class TEA:
    DELTA = 0x9e3779b9
    ROUNDS = 32

    def __init__(self, key):
        self.key = key  # key should be a tuple of four integers

    def encrypt_block(self, m):
        y, z = m
        sum = 0
        for _ in range(TEA.ROUNDS):
            sum = (sum + TEA.DELTA) & 0xffffffff
            y = (y + (((z << 4) + self.key[0]) ^ (z + sum) ^ ((z >> 5) + self.key[1]))) & 0xffffffff
            z = (z + (((y << 4) + self.key[2]) ^ (y + sum) ^ ((y >> 5) + self.key[3]))) & 0xffffffff
        return (y, z)

    def decrypt_block(self, m):
        y, z = m
        sum = (TEA.DELTA * TEA.ROUNDS) & 0xffffffff
        for _ in range(TEA.ROUNDS):
            z = (z - (((y << 4) + self.key[2]) ^ (y + sum) ^ ((y >> 5) + self.key[3]))) & 0xffffffff
            y = (y - (((z << 4) + self.key[0]) ^ (z + sum) ^ ((z >> 5) + self.key[1]))) & 0xffffffff
            sum = (sum - TEA.DELTA) & 0xffffffff
        return (y, z)

    def bytes_to_ints(self, block):
        """Convert a block of 8 bytes to two integers."""
        y = int.from_bytes(block[:4], byteorder='big')
        z = int.from_bytes(block[4:], byteorder='big')
        return y, z

    def ints_to_bytes(self, y, z):
        """Convert two integers to a block of 8 bytes."""
        return y.to_bytes(4, byteorder='big') + z.to_bytes(4, byteorder='big')

    def process_bmp(self, filename, operation, mode, iv=None):
        with open(filename, "rb") as f:
            header = f.read(54)  # BMP header
            body = f.read()

        # Ensure every block is exactly 8 bytes
        if len(body) % 8 != 0:
            # Calculate the number of bytes needed to make the body a multiple of 8
            padding_length = 8 - (len(body) % 8)
            # Append the necessary number of null bytes (b'\x00')
            body += b'\x00' * padding_length

        blocks = [self.bytes_to_ints(body[i:i+8]) for i in range(0, len(body), 8)]
        processed_blocks = []

        if mode == "CBC" and iv is not None:
            previous_block = self.bytes_to_ints(iv)

        for i, block in enumerate(blocks):
            if mode == "CBC" and operation == "encrypt":
                block = (block[0] ^ previous_block[0], block[1] ^ previous_block[1])

            if operation == "encrypt":
                block = self.encrypt_block(block)
            else:
                block = self.decrypt_block(block)

            if mode == "CBC" and operation == "decrypt":
                block = (block[0] ^ previous_block[0], block[1] ^ previous_block[1])

            if mode == "CBC":
                previous_block = block if operation == "encrypt" else blocks[i]

            processed_blocks.append(block)

        output_data = b''.join(self.ints_to_bytes(*block) for block in processed_blocks)
        output_filename = f"{'encrypted' if operation == 'encrypt' else 'decrypted'}.bmp"
        with open(output_filename, "wb") as f:
            f.write(header + output_data)
        print(f"Process completed. Output saved to '{output_filename}'.")

def main():
    while True:
        operation = input("Enter operation (encrypt/decrypt) or 'end' to exit: ")
        if operation.lower() == 'end':
            break
        mode = input("Enter mode (ECB/CBC): ")
        if mode not in ['ECB', 'CBC']:
            print("Invalid mode. Please enter 'ECB' or 'CBC'.")
            continue
        key_input = input("Enter key (4x32 bits hex, separated by spaces): ")
        key = tuple(int(k, 16) for k in key_input.split())
        iv = None
        if mode == 'CBC':
            iv_input = input("Enter IV (2x32 bits hex, separated by spaces): ")
            iv = bytes.fromhex(iv_input.replace(" ", ""))
        filename = input("Enter the filename of the BMP file: ")
        tea = TEA(key)
        tea.process_bmp(filename, operation.lower(), mode, iv)

if __name__ == "__main__":
    main()
