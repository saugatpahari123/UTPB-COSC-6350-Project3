import socket
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from Crypto import keys

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
OUTPUT_FILE = 'reconstructed_file.txt'
KNOWN_PAYLOAD = "The quick brown fox jumps over the lazy dog."

def aes_decrypt(data, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode('utf-8')

def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # Receive total crumbs
        total_crumbs = int(client_socket.recv(1024).decode('utf-8'))
        client_socket.sendall(b'ACK')

        decoded_crumbs = [None] * total_crumbs
        decoded_count = 0

        # Convert keys dict to a list of (crumb_str, key_hex) for random access
        key_items = list(keys.items())

        while decoded_count < total_crumbs:
            data = client_socket.recv(2048)

            if data == b'END':
                # Transmission ended
                break

            if data.startswith(b'PROGRESS:'):
                # This is a server progress message
                server_progress = data.decode('utf-8').split(':')[1]
                print(f"[INFO] Server updated progress: {server_progress}%")
                continue

            # Find first None crumb to decode
            try:
                target_index = decoded_crumbs.index(None)
            except ValueError:
                # No None found, all done
                client_socket.sendall(b"DONE")
                break

            # Attempt to decode with random keys
            random_keys = key_items[:]
            random.shuffle(random_keys)
            successfully_decoded = False

            for crumb_bits, key_hex in random_keys:
                try:
                    decrypted = aes_decrypt(data, key_hex)
                    if decrypted == KNOWN_PAYLOAD:
                        decoded_crumbs[target_index] = crumb_bits
                        decoded_count += 1
                        client_socket.sendall(f"DECODED:{target_index}".encode('utf-8'))
                        successfully_decoded = True
                        break
                except Exception:
                    # Try next key
                    pass

            if not successfully_decoded:
                client_socket.sendall(b"INVALID")

        # Once all crumbs are decoded, reconstruct the file if possible
        if None not in decoded_crumbs:
            # Reconstruct original bytes
            byte_values = []
            for i in range(0, total_crumbs, 4):
                c0 = int(decoded_crumbs[i], 2)
                c1 = int(decoded_crumbs[i+1], 2)
                c2 = int(decoded_crumbs[i+2], 2)
                c3 = int(decoded_crumbs[i+3], 2)
                byte_val = (c0 << 6) | (c1 << 4) | (c2 << 2) | c3
                byte_values.append(byte_val)

            with open(OUTPUT_FILE, 'wb') as f:
                f.write(bytes(byte_values))
            print(f"[INFO] File reconstruction complete. Saved as {OUTPUT_FILE}.")
        else:
            print("[WARNING] Some crumbs were not decoded.")

        print("[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()
