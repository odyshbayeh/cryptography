import struct
from PIL import Image
import binascii

DELTA = 0x9E3779B9

def encrypt_block(v, k):
    y, z = v
    sum = 0
    for _ in range(32):
        sum = (sum + DELTA) & 0xffffffff
        y = (y + ((z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1])) & 0xffffffff
        z = (z + ((y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3])) & 0xffffffff
    return y, z

def decrypt_block(v, k):
    y, z = v
    sum = (DELTA * 32) & 0xffffffff
    for _ in range(32):
        z = (z - ((y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3])) & 0xffffffff
        y = (y - ((z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1])) & 0xffffffff
        sum = (sum - DELTA) & 0xffffffff
    return y, z

def pad(data):
    padding = 8 - len(data) % 8
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def str_to_blocks(data):
    return [(struct.unpack('>II', data[i:i + 8])) for i in range(0, len(data), 8)]

def blocks_to_str(blocks):
    return b''.join([struct.pack('>II', *block) for block in blocks])

def tea_ecb_encrypt(plaintext, key):
    key_tuple = struct.unpack('>IIII', key)
    padded_plaintext = pad(plaintext)
    blocks = str_to_blocks(padded_plaintext)
    encrypted_blocks = [encrypt_block(block, key_tuple) for block in blocks]
    return blocks_to_str(encrypted_blocks)

def tea_ecb_decrypt(ciphertext, key):
    key_tuple = struct.unpack('>IIII', key)
    blocks = str_to_blocks(ciphertext)
    decrypted_blocks = [decrypt_block(block, key_tuple) for block in blocks]
    decrypted_data = blocks_to_str(decrypted_blocks)
    return unpad(decrypted_data)

def tea_cbc_encrypt(plaintext, key, iv):
    key_tuple = struct.unpack('>IIII', key)
    iv_block = struct.unpack('>II', iv)
    padded_plaintext = pad(plaintext)
    blocks = str_to_blocks(padded_plaintext)
    encrypted_blocks = []
    previous_block = iv_block
    for block in blocks:
        block = (block[0] ^ previous_block[0], block[1] ^ previous_block[1])
        encrypted_block = encrypt_block(block, key_tuple)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block
    return blocks_to_str(encrypted_blocks)

def tea_cbc_decrypt(ciphertext, key, iv):
    key_tuple = struct.unpack('>IIII', key)
    iv_block = struct.unpack('>II', iv)
    blocks = str_to_blocks(ciphertext)
    decrypted_blocks = []
    previous_block = iv_block
    for block in blocks:
        decrypted_block = decrypt_block(block, key_tuple)
        decrypted_block = (decrypted_block[0] ^ previous_block[0], decrypted_block[1] ^ previous_block[1])
        decrypted_blocks.append(decrypted_block)
        previous_block = block
    decrypted_data = blocks_to_str(decrypted_blocks)
    return unpad(decrypted_data)

def encrypt_image(image_path, key, iv):
    # Load the image and convert to byte array
    with Image.open(image_path) as img:
        img = img.convert('L')
        img_bytes = img.tobytes()
        mode = img.mode
        size = img.size

    # Encrypt the image bytes using both ECB and CBC
    ecb_encrypted = tea_ecb_encrypt(img_bytes, key)
    cbc_encrypted = tea_cbc_encrypt(img_bytes, key, iv)

    # Save the encrypted images as .bmp
    ecb_encrypted_img = Image.frombytes(mode, size, ecb_encrypted)
    ecb_encrypted_img.save("ecb_encrypted_image.bmp")

    cbc_encrypted_img = Image.frombytes(mode, size, cbc_encrypted)
    cbc_encrypted_img.save("cbc_encrypted_image.bmp")

    # Decrypt the images back to verify
    ecb_decrypted = tea_ecb_decrypt(ecb_encrypted, key)
    cbc_decrypted = tea_cbc_decrypt(cbc_encrypted, key, iv)

    # Save the decrypted images as .bmp
    ecb_decrypted_img = Image.frombytes(mode, size, ecb_decrypted)
    ecb_decrypted_img.save("ecb_decrypted_image.bmp")

    cbc_decrypted_img = Image.frombytes(mode, size, cbc_decrypted)
    cbc_decrypted_img.save("cbc_decrypted_image.bmp")

def main():
    # Prompt the user to enter the key
    while True:
        try:
            key_input = input("Enter the key as a 32-character hexadecimal string: ")
            if len(key_input) != 32:
                raise ValueError("Key must be exactly 32 characters.")
            key = binascii.unhexlify(key_input)
            break
        except ValueError as e:
            print(e)
            print("Please try again.")

    # Prompt the user to enter the IV
    while True:
        try:
            iv_input = input("Enter the IV as a 16-character hexadecimal string: ")
            if len(iv_input) != 16:
                raise ValueError("IV must be exactly 16 characters.")
            iv = binascii.unhexlify(iv_input)
            break
        except ValueError as e:
            print(e)
            print("Please try again.")
            
    image_path = input("Please enter the path of the image: ")
    encrypt_image(image_path, key, iv)

if __name__ == "__main__":
    main()
