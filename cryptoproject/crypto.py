import struct
from typing import List, Tuple
from PIL import Image
import binascii

DELTA = 0x9E3779B9

class TEA:
    def __init__(self, key: bytes):
        self.key = struct.unpack('>IIII', key)

    def encrypt_block(self, v: Tuple[int, int]) -> Tuple[int, int]:
        y, z = v
        sum = 0
        for _ in range(32):
            sum = (sum + DELTA) & 0xffffffff
            y = (y + ((z << 4) + self.key[0] ^ z + sum ^ (z >> 5) + self.key[1])) & 0xffffffff
            z = (z + ((y << 4) + self.key[2] ^ y + sum ^ (y >> 5) + self.key[3])) & 0xffffffff
        return y, z

    def decrypt_block(self, v: Tuple[int, int]) -> Tuple[int, int]:
        y, z = v
        sum = (DELTA * 32) & 0xffffffff
        for _ in range(32):
            z = (z - ((y << 4) + self.key[2] ^ y + sum ^ (y >> 5) + self.key[3])) & 0xffffffff
            y = (y - ((z << 4) + self.key[0] ^ z + sum ^ (z >> 5) + self.key[1])) & 0xffffffff
            sum = (sum - DELTA) & 0xffffffff
        return y, z

    @staticmethod
    def pad(data: bytes) -> bytes:
        padding = 8 - len(data) % 8
        return data + bytes([padding] * padding)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        padding = data[-1]
        return data[:-padding]

    @staticmethod
    def str_to_blocks(data: bytes) -> List[Tuple[int, int]]:
        return [struct.unpack('>II', data[i:i + 8]) for i in range(0, len(data), 8)]

    @staticmethod
    def blocks_to_str(blocks: List[Tuple[int, int]]) -> bytes:
        return b''.join([struct.pack('>II', *block) for block in blocks])

    def ecb_encrypt(self, plaintext: bytes) -> bytes:
        padded_plaintext = self.pad(plaintext)
        blocks = self.str_to_blocks(padded_plaintext)
        encrypted_blocks = [self.encrypt_block(block) for block in blocks]
        return self.blocks_to_str(encrypted_blocks)

    def ecb_decrypt(self, ciphertext: bytes) -> bytes:
        blocks = self.str_to_blocks(ciphertext)
        decrypted_blocks = [self.decrypt_block(block) for block in blocks]
        decrypted_data = self.blocks_to_str(decrypted_blocks)
        return self.unpad(decrypted_data)

    def cbc_encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        iv_block = struct.unpack('>II', iv)
        padded_plaintext = self.pad(plaintext)
        blocks = self.str_to_blocks(padded_plaintext)
        encrypted_blocks = []
        previous_block = iv_block

        for block in blocks:
            block = (block[0] ^ previous_block[0], block[1] ^ previous_block[1])
            encrypted_block = self.encrypt_block(block)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return self.blocks_to_str(encrypted_blocks)

    def cbc_decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        iv_block = struct.unpack('>II', iv)
        blocks = self.str_to_blocks(ciphertext)
        decrypted_blocks = []
        previous_block = iv_block

        for block in blocks:
            decrypted_block = self.decrypt_block(block)
            decrypted_block = (decrypted_block[0] ^ previous_block[0], decrypted_block[1] ^ previous_block[1])
            decrypted_blocks.append(decrypted_block)
            previous_block = block

        decrypted_data = self.blocks_to_str(decrypted_blocks)
        return self.unpad(decrypted_data)

def load_image(image_path: str) -> Tuple[bytes, str, Tuple[int, int]]:
    with Image.open(image_path) as img:
        img = img.convert('L')  # Convert to grayscale
        img_bytes = img.tobytes()
        return img_bytes, img.mode, img.size

def save_image(image_bytes: bytes, mode: str, size: Tuple[int, int], path: str):
    img = Image.frombytes(mode, size, image_bytes)
    img.save(path)

def encrypt_image(image_path: str, key: bytes, iv: bytes = None, mode: str = "ECB"):
    img_bytes, img_mode, img_size = load_image(image_path)
    tea = TEA(key)

    if mode == "ECB":
        encrypted_bytes = tea.ecb_encrypt(img_bytes)
        decrypted_bytes = tea.ecb_decrypt(encrypted_bytes)
        save_image(encrypted_bytes, img_mode, img_size, "ecb_encrypted_image.png")
        save_image(decrypted_bytes, img_mode, img_size, "ecb_decrypted_image.png")
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV must be provided for CBC mode.")
        encrypted_bytes = tea.cbc_encrypt(img_bytes, iv)
        decrypted_bytes = tea.cbc_decrypt(encrypted_bytes, iv)
        save_image(encrypted_bytes, img_mode, img_size, "cbc_encrypted_image.png")
        save_image(decrypted_bytes, img_mode, img_size, "cbc_decrypted_image.png")

def main():
    while True:
        mode = input("Enter the mode (ECB or CBC) or 'end' to exit: ").strip().upper()
        if mode == "END":
            break
        if mode not in ["ECB", "CBC"]:
            print("Invalid mode. Please enter ECB or CBC.")
            continue
        
        key_hex = input("Enter the key (32 hex digits): ").strip()
        if len(key_hex) != 32:
            print("Invalid key length. The key must be 32 hex digits.")
            continue
        
        try:
            key = binascii.unhexlify(key_hex)
        except binascii.Error:
            print("Invalid key format. Please enter valid hex digits.")
            continue

        iv = None
        if mode == "CBC":
            iv_hex = input("Enter the IV (16 hex digits): ").strip()
            if len(iv_hex) != 16:
                print("Invalid IV length. The IV must be 16 hex digits.")
                continue

            try:
                iv = binascii.unhexlify(iv_hex)
            except binascii.Error:
                print("Invalid IV format. Please enter valid hex digits.")
                continue

        image_path = input("Enter the image path or filename with extension: ").strip()
        try:
            encrypt_image(image_path, key, iv, mode)
            print(f"Encrypted and decrypted images have been saved for {mode} mode.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
