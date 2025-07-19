import numpy as np
from PIL import Image

class TEA:
    DELTA = np.uint32(0x9e3779b9)
    ROUNDS = 32

    def __init__(self, key):
        if len(key) != 4:
            raise ValueError("Key must be exactly 128 bits (4 integers).")
        self.key = np.array(key, dtype=np.uint32)

    def encrypt_block(self, block):
        left, right = np.uint32(block[0]), np.uint32(block[1])
        sum = np.uint32(0)
        for _ in range(self.ROUNDS):
            sum += self.DELTA
            left += ((right << 4) + self.key[0]) ^ (right + sum) ^ ((right >> 5) + self.key[1])
            right += ((left << 4) + self.key[2]) ^ (left + sum) ^ ((left >> 5) + self.key[3])
        return [left, right]

    def decrypt_block(self, block):
        left, right = np.uint32(block[0]), np.uint32(block[1])
        sum = self.DELTA * self.ROUNDS
        for _ in range(self.ROUNDS):
            right -= ((left << 4) + self.key[2]) ^ (left + sum) ^ ((left >> 5) + self.key[3])
            left -= ((right << 4) + self.key[0]) ^ (right + sum) ^ ((right >> 5) + self.key[1])
            sum -= self.DELTA
        return [left, right]

class ECBmode(TEA):
    def encrypt(self, blocks):
        return [self.encrypt_block(block) for block in blocks]

    def decrypt(self, blocks):
        return [self.decrypt_block(block) for block in blocks]

class CBCmode(TEA):
    def encrypt(self, blocks, iv):
        encrypted_blocks = []
        previous_block = iv
        for block in blocks:
            block = [block[0] ^ previous_block[0], block[1] ^ previous_block[1]]
            encrypted_block = self.encrypt_block(block)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block
        return encrypted_blocks

    def decrypt(self, blocks, iv):
        decrypted_blocks = []
        previous_block = iv
        for block in blocks:
            decrypted_block = self.decrypt_block(block)
            decrypted_block = [decrypted_block[0] ^ previous_block[0], decrypted_block[1] ^ previous_block[1]]
            decrypted_blocks.append(decrypted_block)
            previous_block = block
        return decrypted_blocks

def image_to_blocks(image_data):
    h, w = image_data.shape
    blocks = []
    for i in range(0, h, 2):
        for j in range(0, w, 2):
            if i + 1 < h and j + 1 < w:
                block = [
                    (image_data[i, j] << 16) + (image_data[i, j] << 8) + image_data[i, j],
                    (image_data[i + 1, j] << 16) + (image_data[i + 1, j] << 8) + image_data[i + 1, j]
                ]
            elif i + 1 < h:
                block = [
                    (image_data[i, j] << 16) + (image_data[i, j] << 8) + image_data[i, j],
                    0
                ]
            elif j + 1 < w:
                block = [
                    (image_data[i, j] << 16) + (image_data[i, j] << 8) + image_data[i, j],
                    0
                ]
            else:
                block = [
                    (image_data[i, j] << 16) + (image_data[i, j] << 8) + image_data[i, j],
                    0
                ]
            blocks.append(block)
    return blocks

def blocks_to_image(blocks, h, w):
    image_data = np.zeros((h, w), dtype=np.uint8)
    idx = 0
    for i in range(0, h, 2):
        for j in range(0, w, 2):
            block = blocks[idx]
            image_data[i, j] = (block[0] >> 16) & 0xFF
            if i + 1 < h:
                image_data[i + 1, j] = (block[1] >> 16) & 0xFF
            if j + 1 < w:
                image_data[i, j + 1] = (block[0] >> 8) & 0xFF
                if i + 1 < h:
                    image_data[i + 1, j + 1] = block[1] & 0xFF
            idx += 1
    return image_data

def get_key_from_user():
    while True:
        try:
            key_input = input("Enter 4 hexadecimal integers for the key, separated by spaces: ")
            key = [int(x, 16) for x in key_input.split()]
            if len(key) != 4:
                raise ValueError("You must enter exactly 4 hexadecimal integers.")
            return key
        except ValueError as e:
            print(e)
            print("Please try again.")

def main():
    key = get_key_from_user()

    # Load the image
    image = Image.open('Aqsa.bmp').convert('L')
    image_data = np.array(image)
    print("Original Image Data:", image_data)

    # Convert the image to blocks
    blocks = image_to_blocks(image_data)
    iv = [0, 0]
    print("Original Blocks:", blocks)

    # Encrypt and decrypt using ECB mode
    ecb = ECBmode(key)
    encrypted_blocks_ecb = ecb.encrypt(blocks)
    print("Encrypted Blocks ECB:", encrypted_blocks_ecb)
    encrypted_image_data_ecb = blocks_to_image(encrypted_blocks_ecb, image_data.shape[0], image_data.shape[1])
    Image.fromarray(encrypted_image_data_ecb).save('encrypted_ecb.bmp')

    decrypted_blocks_ecb = ecb.decrypt(encrypted_blocks_ecb)
    print("Decrypted Blocks ECB:", decrypted_blocks_ecb)
    decrypted_image_data_ecb = blocks_to_image(decrypted_blocks_ecb, image_data.shape[0], image_data.shape[1])
    Image.fromarray(decrypted_image_data_ecb).save('decrypted_ecb.bmp')

    # Encrypt and decrypt using CBC mode
    cbc = CBCmode(key)
    encrypted_blocks_cbc = cbc.encrypt(blocks, iv)
    print("Encrypted Blocks CBC:", encrypted_blocks_cbc)
    encrypted_image_data_cbc = blocks_to_image(encrypted_blocks_cbc, image_data.shape[0], image_data.shape[1])
    Image.fromarray(encrypted_image_data_cbc).save('encrypted_cbc.bmp')

    decrypted_blocks_cbc = cbc.decrypt(encrypted_blocks_cbc, iv)
    print("Decrypted Blocks CBC:", decrypted_blocks_cbc)
    decrypted_image_data_cbc = blocks_to_image(decrypted_blocks_cbc, image_data.shape[0], image_data.shape[1])
    Image.fromarray(decrypted_image_data_cbc).save('decrypted_cbc.bmp')

if __name__ == '__main__':
    main()
