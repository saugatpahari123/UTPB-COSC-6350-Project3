# Server.py
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
from Crypto import keys  # Load keys dictionary from Crypto.py

# Constants
HOST = '127.0.0.1'
PORT = 5555
FILE_PATH = 'file_to_send.txt'

# Encrypt data using AES with the given key
def aes_encrypt(data, key):
    key_bytes = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

# Handle each client connection
def handle_client(client_socket, file_bytes, crumbs):
    try:
        total_crumbs = len(crumbs)
        client_socket.send(str(total_crumbs).encode('utf-8'))
        client_socket.recv(1024)  # Wait for ACK

        progress = [False] * total_crumbs

        while not all(progress):
            for index, crumb in enumerate(crumbs):
                if progress[index]:
                    continue

                key = keys.get(crumb)
                if key is None:
                    print(f"[ERROR] Key not found for crumb: {crumb}")
                    continue
                chunk = file_bytes[index:index + 16]
                encrypted_data = aes_encrypt(chunk, key).hex().encode('utf-8')
                client_socket.send(encrypted_data)

                response = client_socket.recv(1024)
                if response == b'ACK':
                    progress[index] = True

        client_socket.send(b'END')
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()

# Main server logic
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[INFO] Server listening on {HOST}:{PORT}")

        with open(FILE_PATH, 'rb') as f:
            file_bytes = f.read()

        crumbs = []
        for byte in file_bytes:
            crumb1 = f"{(byte >> 6) & 0b11:02b}"
            crumb2 = f"{(byte >> 4) & 0b11:02b}"
            if crumb1 in keys and crumb2 in keys:
                crumbs.extend([crumb1, crumb2])
        crumbs = []
        for byte in file_bytes:
            crumb1 = f"{(byte >> 6) & 0b11:02b}"
            crumb2 = f"{(byte >> 4) & 0b11:02b}"
            if crumb1 in keys and crumb2 in keys:
                crumbs.append(crumb1)
                crumbs.append(crumb2)

        while True:
            client_socket, addr = server_socket.accept()
            print(f"[INFO] Connection from {addr} established.")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, file_bytes, crumbs))
            client_thread.start()

if __name__ == "__main__":
    start_server()
