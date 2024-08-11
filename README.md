# Secure File Transfer Application

This project implements a secure file transfer application using RSA and AES encryption, along with HMAC for data integrity verification. The application allows two users to securely exchange files, ensuring the confidentiality and integrity of the transferred data.

## Features

- **RSA Encryption**: RSA is used for securely exchanging the AES encryption key and the HMAC key between users.
- **AES Encryption**: AES in CBC mode is used for encrypting the actual file content, ensuring data confidentiality.
- **HMAC**: HMAC (Hash-based Message Authentication Code) is used to verify the integrity and authenticity of the received files.
- **End-to-End Encryption**: The application provides end-to-end encryption, ensuring that only the intended recipient can decrypt and access the file.
- **Dual Roles**: Both User A and User B can act as either a sender or receiver of files, depending on the selected option.

## How It Works

1. **Generate RSA Keys**: Each user must generate their RSA key pair before starting the file transfer.
2. **Choose Action**: Users can choose to either send or receive a file.
   - **Sending**: The selected file is encrypted and transmitted securely.
   - **Receiving**: The received file is decrypted and verified for integrity using the provided HMAC.
3. **Secure Communication**: The AES key and HMAC key are securely exchanged using RSA encryption.

### File Transfer Process

1. **Client**:
   - The client connects to the server and receives the server's public RSA key.
   - The client generates a random AES key for file encryption and a random HMAC key for integrity verification.
   - The AES key and HMAC key are encrypted with the server's public RSA key and sent to the server.
   - The client encrypts the file using AES in CBC mode, then computes the HMAC of the file's content.
   - The client sends the encrypted file, the initialization vector (IV) for AES, the encrypted HMAC key, and the HMAC digest to the server.

2. **Server**:
   - The server generates an RSA key pair (public and private keys).
   - The public key is shared with the client to encrypt the AES and HMAC keys.
   - The server receives the encrypted AES key and HMAC key, decrypts them using its private RSA key.
   - The server receives the IV, encrypted file, and HMAC digest.
   - The server decrypts the file using the AES key and verifies its integrity using the HMAC.

### File Integrity Verification

- The integrity of the received file is verified using HMAC. If the computed HMAC does not match the received HMAC, the file is flagged as potentially tampered or corrupted.

## Usage

### User A:
- **Send a File**: When User A selects the option to send a file, the client code is executed, encrypting the file and sending it to User B. **Note:** User B must be in "Receive a File" mode for the file transfer to occur successfully.
- **Receive a File**: When User A selects the option to receive a file, the server code is executed, allowing User A to receive and decrypt the file from User B. **Note:** User B must be in "Send a File" mode for the file transfer to proceed.

### User B:
- **Send a File**: When User B selects the option to send a file, the client code is executed, encrypting the file and sending it to User A. **Note:** User A must be in "Receive a File" mode for the file transfer to occur successfully.
- **Receive a File**: When User B selects the option to receive a file, the server code is executed, allowing User B to receive and decrypt the file from User A. **Note:** User A must be in "Send a File" mode for the file transfer to proceed.

This ensures that the file transfer process is synchronized between the two users.

## Running the Code

- **User A**: 
  - To send a file: Run the client code.
  - To receive a file: Run the server code.
  
- **User B**: 
  - To send a file: Run the client code.
  - To receive a file: Run the server code.

Ensure that both users agree on who will act as the sender and receiver before initiating the transfer.


## Requirements

- Python 3.x
- PyCryptodome library

You can install the required library using:

```bash
pip install pycryptodome
```

## Usage

1. Clone the repository:

```bash
git clone https://github.com/your-username/secure-file-transfer.git
cd secure-file-transfer
```

2. Run User A:

```bash
python UserA.py
```

3. Run UserB :

```bash
python UserB.py
```

4. Follow the on-screen instructions to either send or receive a file.

Feel free to customize this content further based on your project specifics!
