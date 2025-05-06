import socket
import threading
import base64
import struct
from crypto_utils import (
    generate_rsa_keypair,
    encrypt_with_rsa,
    decrypt_with_rsa,
    generate_aes_key,
    encrypt_with_aes,
    decrypt_with_aes
)

# RSA Key Generation
private_key, public_key = generate_rsa_keypair()

clients = {}  # client_socket -> (addr, aes_key)

def handle_client(client_socket, addr):
    try:
        # Step 1: Send RSA Public Key
        client_socket.send(struct.pack('>I', len(public_key)))
        client_socket.send(public_key)

        # Step 2: Receive Encrypted AES Key
        key_length_data = client_socket.recv(4)
        key_length = struct.unpack('>I', key_length_data)[0]
        encrypted_key = client_socket.recv(key_length)

        # Step 3: Decrypt AES Key
        aes_key = decrypt_with_rsa(private_key, encrypted_key)
        clients[client_socket] = (addr, aes_key)
        print(f"[+] AES key received and decrypted from {addr}")

        while True:
            msg_length_data = client_socket.recv(4)
            if not msg_length_data:
                break
            msg_length = struct.unpack('>I', msg_length_data)[0]
            enc_message = client_socket.recv(msg_length)
            enc_message = enc_message.decode()

            print(f"[{addr}] {enc_message}")

            # Broadcast
            for other_socket in clients:
                if other_socket != client_socket:
                    other_key = clients[other_socket][1]
                    try:
                        # Decrypt with sender's AES
                        plaintext = decrypt_with_aes(aes_key, enc_message)

                        # Re-encrypt with receiver's AES
                        re_encrypted = encrypt_with_aes(other_key, plaintext)

                        # Send
                        msg_bytes = re_encrypted.encode()
                        other_socket.send(struct.pack('>I', len(msg_bytes)))
                        other_socket.send(msg_bytes)
                    except Exception as e:
                        print(f"[!] Error decrypting or sending message: {e}")

    finally:
        print(f"[-] Client disconnected: {addr}")
        del clients[client_socket]
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 5555))
    server.listen(5)
    print("[*] Server listening on port 5555")
    while True:
        client_socket, addr = server.accept()
        print(f"[+] Client connected from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
