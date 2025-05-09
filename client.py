import socket
import struct
import threading
from crypto_utils import encrypt_with_rsa, decrypt_with_aes

aes_key = None

def receive_messages(sock):
    global aes_key
    while True:
        try:
            msg_length_data = sock.recv(4)
            if not msg_length_data:
                break
            msg_length = struct.unpack('>I', msg_length_data)[0]
            enc_message = sock.recv(msg_length).decode()

            try:
                plaintext = decrypt_with_aes(aes_key, enc_message)
                print(f"\n[Received] {plaintext}")
            except Exception as e:
                print(f"\n[Received] [!] Error decrypting message: {e}")
        except:
            break

def main():
    global aes_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates socket and immedialy connects to the server on port 5555
    sock.connect(("127.0.0.1", 5555))

    # Receive RSA Public Key
    key_length_data = sock.recv(4)
    key_length = struct.unpack('>I', key_length_data)[0]
    public_key = sock.recv(key_length)

    # Generate AES Key and send encrypted to server
    from crypto_utils import generate_aes_key
    aes_key = generate_aes_key()
    encrypted_key = encrypt_with_rsa(public_key, aes_key)
    sock.send(struct.pack('>I', len(encrypted_key)))  #using struct.pack to fiz the padding issue
    sock.send(encrypted_key)
    print("[+] AES key generated and sent securely.")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    while True:
        msg = input("Enter message: ")
        from crypto_utils import encrypt_with_aes
        enc = encrypt_with_aes(aes_key, msg)
        msg_bytes = enc.encode()
        sock.send(struct.pack('>I', len(msg_bytes)))
        sock.send(msg_bytes)

if __name__ == "__main__":
    main()
