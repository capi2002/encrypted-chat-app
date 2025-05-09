# Secure UDP Chat Application

A Python-based secure chat application using UDP sockets with hybrid encryption (RSA for key exchange and AES for message encryption).


## Libraries Used

- Socket
- Threading
- Crypto.Cipher, Crypto.Random, Crypto.Util.Padding
- base64
- structure


## Encryption

- **RSA (Public Key Cryptography)** is used to exchange AES keys securely.
- **AES (Advanced Encryption Standard)** is used for encrypting messages between clients.
- **Base64 encoding** is used to safely transmit encrypted binary data as strings.

##  System Requirements

- python3 --version
- pip3 install pycryptodome(If using a virtual environment, activate it first with source venv/bin/activate or similar)


##  How to run
**Ensure your working directory contains:**
- server.py
- client.py
- crypto_utils.py
**You’ll need at least 3 terminal windows:**
- Terminal 1: Start the server by using the command "python3 server.py on the terminal"
- Terminal 2: Start the first client by using the command "python3 client.py"
- Terminal 3: Start client 2 by using the same command as terminal 2, "python3 client.py"
- You can run more clients by opening more terminals and repeating step 3.


## Key notes when running if not working 

- Make sure all scripts are in the same folder.
- Communication is via localhost (127.0.0.1) by default, so all terminals must be on the same machine.
