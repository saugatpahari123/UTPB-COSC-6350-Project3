from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Predefined encryption keys for 2-bit crumbs
keys = {
    0b00: 0xd7ffe8f10f124c56918a614acfc65814,
    0b01: 0x5526736ddd6c4a0592ed33cbc5b1b76d,
    0b10: 0x88863eef1a37427ea0b867227f09a7c1,
    0b11: 0x45355f125db4449eb07415e8df5e27d4
}


def aes_encrypt(data, key):
    """
    Encrypt data using AES.
    :param data: The data to encrypt (str or bytes).
    :param key: The encryption key (16 bytes for AES-128).
    :return: Encrypted data (bytes).
    """
    if isinstance(data, str):
        print(f"[DEBUG] Encoding string to bytes: {data}")
        data = data.encode()  # Convert string to bytes
    elif isinstance(data, bytes):
        print(f"[DEBUG] Data already in bytes: {data}")
    else:
        raise ValueError(f"[ERROR] Unsupported data type for encryption: {type(data)}")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def aes_decrypt(ciphertext, key):
    try:
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except Exception:
        return None  # Return None for invalid ciphertext


def decompose_byte(byte):
    crumbs = []
    for _ in range(4):
        crumbs.append(byte & 0b11)
        byte >>= 2
    return crumbs[::-1]

def recompose_byte(crumbs):
    byte = 0
    for crumb in crumbs:
        byte = (byte << 2) | crumb
    return byte
