import socket
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Constants
HOST = '0.0.0.0'
PORT = 5555
TIMEOUT = 600
SOME_STRING = "The quick brown fox jumps over the lazy dog."
PACKET_SIZE = 1024  # Define a size to split the string if needed

# AES encryption
def aes_encrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print(f"[INFO] Connection from {addr} established.")

    try:
        # Split the string into packets
        packets = [SOME_STRING[i:i + PACKET_SIZE] for i in range(0, len(SOME_STRING), PACKET_SIZE)]
        total_packets = len(packets)
        print(f"[INFO] Total packets to send: {total_packets}")

        # Send total packet count to the client
        conn.sendall(str(total_packets).encode())
        client_ack = conn.recv(1024)
        if client_ack != b'ACK':
            print("[ERROR] Did not receive ACK from client.")
            return

        # Send encrypted packets
        for i, packet in enumerate(packets):
            key = hashlib.sha256(f"packet-{i}".encode()).digest()[:16]  # Generate unique key
            encrypted_packet = aes_encrypt(packet, key)
            conn.sendall(encrypted_packet)

            try:
                ack = conn.recv(1024)
                if ack != b'ACK':
                    print(f"[WARN] Invalid ACK for packet {i}. Resending...")
                    conn.sendall(encrypted_packet)
            except socket.timeout:
                print(f"[WARN] Timeout for packet {i}. Resending...")
                conn.sendall(encrypted_packet)

        # Send end signal
        conn.sendall(b'END')
        print("[INFO] Transmission complete.")

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()
        print(f"[INFO] Connection from {addr} closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[INFO] Server started on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    start_server()
