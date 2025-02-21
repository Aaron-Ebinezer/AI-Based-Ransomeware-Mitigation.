from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os


def pad(data):
    # PKCS7 padding
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)


def encrypt_pe_file_inplace(file_path):
    try:
        # Generate AES key and IV
        key = get_random_bytes(16)  # 128-bit key
        iv = get_random_bytes(16)

        # Read the PE file
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Apply padding
        padded_plaintext = pad(plaintext)

        # Encrypt using AES CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Overwrite the original file with IV + ciphertext
        with open(file_path, 'wb') as f:
            f.write(iv + ciphertext)

        print(f"[SUCCESS] File encrypted in place: {file_path}")

    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")


if __name__ == "__main__":
    input_pe_file = r"C:\\mini project\\test\\minimal.exe"

    if os.path.exists(input_pe_file):
        encrypt_pe_file_inplace(input_pe_file)
    else:
        print(f"[ERROR] File not found: {input_pe_file}")
