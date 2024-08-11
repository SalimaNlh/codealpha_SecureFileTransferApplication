# Terminal Code for Secure File Transfer

## Overview

This repository contains Python scripts for a secure file transfer application using RSA and AES encryption. The code operates in the terminal without a graphical interface and allows both users to act as either a server or a client. It ensures secure data transfer between two users by encrypting and decrypting files, as well as verifying their integrity.

## Components

The code includes two scripts:

- **UserA.py**: A script that can function as either a server or a client.
- **UserB.py**: A script that can function as either a server or a client.

## Usage

### Running the Scripts

1. **Open a terminal and run  `UserA.py` and `UserB.py`in two differents terminal**
2. **Choose an action from the menu:**
   - **Send a File**: Encrypt and send a file to the other user.
   - **Receive a File**: Receive and decrypt a file from the other user.
   - **Exit**: Exit the script.

### Synchronization Note

- Both users must coordinate their actions. If one user is set to receive a file, the other must be set to send a file, and vice versa.
- **Both users cannot perform the same action simultaneously** (e.g., both cannot be in "send" mode or both in "receive" mode at the same time). Ensure synchronization for successful file transfer.

### Example

1. **User A** runs the script and selects "Receive a File".
2. **User B** runs the script and selects "Send a File".
3. **User A** waits for the connection on port 1000.
4. **User B** connects to User A on port 1000 and sends the file.

## Requirements

- Python 3.x
- `pycryptodome` library (install with `pip install pycryptodome`)

## Notes

- Ensure both users are running their respective scripts and are connected to the same network.
- Make sure port 1000 is open and not blocked by a firewall.

## License

This code is provided as-is without any warranty. Use it at your own risk.

---

Feel free to adjust any specifics or add additional details as necessary!
