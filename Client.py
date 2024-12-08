import socket
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
PACKET_SIZE = 1024

# AES decryption
def aes_decrypt(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # Receive total packet count
        total_packets = int(client_socket.recv(1024).decode())
        print(f"[INFO] Total packets to decode: {total_packets}")
        client_socket.sendall(b'ACK')

        received_data = ""
        for i in range(total_packets):
            encrypted_packet = client_socket.recv(16 + PACKET_SIZE)  # IV + Ciphertext
            key = hashlib.sha256(f"packet-{i}".encode()).digest()[:16]
            try:
                decrypted_packet = aes_decrypt(encrypted_packet, key).decode()
                received_data += decrypted_packet
                client_socket.sendall(b'ACK')
            except Exception as e:
                print(f"[WARN] Failed to decrypt packet {i}: {e}")
                client_socket.sendall(b'NACK')

        end_signal = client_socket.recv(1024)
        if end_signal == b'END':
            print("[INFO] Transmission complete.")
            print(f"[INFO] Received data: {received_data}")
        else:
            print("[WARN] Unexpected end signal.")

if __name__ == "__main__":
    tcp_client()
