import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
from Crypto import keys  # Import the shared keys

# Server Constants
HOST = '127.0.0.1'
PORT = 5555
FILE_PATH = 'file_to_send.txt'
STANDARD_PAYLOAD = "The quick brown fox jumps over the lazy dog."

# Encrypt data using AES with the given key
def aes_encrypt(data, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

def client_handler(client_socket, crumbs):
    """
    Handle communication with a single client:
    - Send total crumb count
    - Wait for ACK
    - Send encrypted packets corresponding to each crumb until 100% decoded by client
    """

    try:
        total_crumbs = len(crumbs)
        # Send total number of crumbs
        client_socket.send(str(total_crumbs).encode('utf-8'))
        ack = client_socket.recv(1024)
        if ack.decode('utf-8') != 'ACK':
            print("[ERROR] Client did not ACK total_crumbs.")
            return

        decoded_count = 0
        current_index = 0

        while decoded_count < total_crumbs:
            crumb = crumbs[current_index]
            key_hex = keys[crumb]
            encrypted_packet = aes_encrypt(STANDARD_PAYLOAD, key_hex)

            # Send the encrypted packet
            client_socket.send(encrypted_packet)

            # Receive client response
            response = client_socket.recv(1024).decode('utf-8')

            if response.startswith("DECODED:"):
                decoded_index = int(response.split(":")[1])
                decoded_count += 1
                progress = (decoded_count / total_crumbs) * 100
                print(f"[INFO] Client decoded crumb {decoded_index}. Progress: {progress:.2f}%")

                # Send updated progress to client
                client_socket.send(f"PROGRESS:{progress:.2f}".encode('utf-8'))
            elif response == "INVALID":
                # Client could not decode this packet. We'll just continue sending.
                pass
            elif response == "DONE":
                break

            current_index = (current_index + 1) % total_crumbs

        # Once done, send END signal
        client_socket.send(b'END')

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()


def start_server():
    # Read file and convert to crumbs
    with open(FILE_PATH, 'rb') as f:
        file_bytes = f.read()

    crumbs = []
    for byte in file_bytes:
        # Extract four 2-bit sequences from the byte
        for shift_amount in [6, 4, 2, 0]:
            crumb_val = (byte >> shift_amount) & 0b11
            crumb_str = f"{crumb_val:02b}"
            if crumb_str in keys:
                crumbs.append(crumb_str)
            # If not in keys, skip silently

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[INFO] Server listening on {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"[INFO] Connection from {addr} established.")
            threading.Thread(target=client_handler, args=(client_socket, crumbs)).start()

if __name__ == "__main__":
    start_server()
