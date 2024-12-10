# Client.py
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from Crypto import keys  # Import keys dictionary

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
OUTPUT_FILE = 'reconstructed_file.txt'

# Decrypt data using AES with the given key
def aes_decrypt(data, key):
    key_bytes = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode('utf-8')

# Client logic
def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            total_crumbs = int(client_socket.recv(1024).decode('utf-8'))
            client_socket.sendall(b'ACK')  # Acknowledge receipt

            crumbs = [None] * total_crumbs
            num_decoded = 0

            while num_decoded < total_crumbs:
                encrypted_data = client_socket.recv(1024)
                if encrypted_data == b'END':
                    print("[INFO] End of transmission.")
                    break
                encrypted_data = bytes.fromhex(encrypted_data.decode('utf-8'))

                if encrypted_data == b'END':
                    print("[INFO] End of transmission.")
                    break

                for crumb, key in keys.items():
                    try:
                        decrypted_chunk = aes_decrypt(encrypted_data, key)
                        if decrypted_message == "some string":
                            crumb_index = crumbs.index(None)
                            crumbs[crumb_index] = crumb
                            num_decoded += 1
                            client_socket.sendall(b'ACK')
                            break
                    except Exception:
                        continue

            with open(OUTPUT_FILE, 'w') as f:
                for crumb in crumbs:
                    if crumb is not None:
                        f.write(crumb)

            print(f"[INFO] File reconstruction complete. Saved as {OUTPUT_FILE}.")
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            print("[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()