import socket
import threading
import PySimpleGUI as sg
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BUFFER_SIZE = 4096

# Function to generate RSA keys
def generate_rsa_keys():
    mykey = RSA.generate(2048)
    public = mykey.public_key().export_key()
    pv = mykey.export_key()
    
    with open('publicA.pem', 'wb') as f:
        f.write(public)
    with open('privateA.pem', 'wb') as f:
        f.write(pv)
    
    return public

# Function to decrypt AES key with RSA private key
def decrypt_aes_key(chiff_aes):
    with open('privateA.pem', 'rb') as f:
        import_private = RSA.import_key(f.read())
    
    cipher = PKCS1_OAEP.new(import_private)
    decrypted_key = cipher.decrypt(chiff_aes)
    return decrypted_key

# Function to decrypt HMAC key with RSA private key
def decrypt_hmac_key(hmac_key):
    with open('privateA.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_hmac_key = cipher.decrypt(hmac_key)
    return decrypted_hmac_key

# Function to receive and decrypt the file
def receive_file(sock_client, dechiff, decrypt_hmac, hmac_received, window):
    iv = sock_client.recv(16)
    if len(iv) != 16:
        raise ValueError("Incorrect IV length (it must be 16 bytes long)")
    
    cipher_aes = AES.new(dechiff, AES.MODE_CBC, iv)
    encrypted_data = b""
    
    while True:
        chunk = sock_client.recv(BUFFER_SIZE)
        if not chunk:
            break
        encrypted_data += chunk

    decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
    
    with open('received_file_A.txt', 'wb') as f:
        f.write(decrypted_data)

    hmac_obj = HMAC.new(decrypt_hmac, digestmod=SHA256)
    hmac_obj.update(decrypted_data)
    
    try:
        hmac_obj.verify(hmac_received)
        window['-OUTPUT-'].print("\nFile decrypted and authenticated successfully.")
    except ValueError:
        window['-OUTPUT-'].print("\nThe file has been modified or is corrupted.")

# Server function to listen and receive files
def server(window):
    public = generate_rsa_keys()
    
    sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_server.bind(('localhost', 1000))
    sock_server.listen(20)
    window['-OUTPUT-'].print("User A listening on port 1000...")
    
    try:
        sock_client, add_client = sock_server.accept()
        window['-OUTPUT-'].print(f"Client connected: {add_client}")
        
        sock_client.sendall(public)
        window['-OUTPUT-'].print("\nPublic key sent.")
        
        chiff_aes = sock_client.recv(256)
        dechiff = decrypt_aes_key(chiff_aes)
        window['-OUTPUT-'].print(f"\nDecrypted AES key: {dechiff}")

        hmac_key = sock_client.recv(256)
        decrypt_hmac = decrypt_hmac_key(hmac_key)
        hmac_received = sock_client.recv(32)

        receive_file(sock_client, dechiff, decrypt_hmac, hmac_received, window)
        
    except KeyboardInterrupt:
        window['-OUTPUT-'].print("Server stopped.")
    finally:
        sock_server.close()

# Function to encrypt and send the file
def encrypt_file(public_RSA, aes_key, file_path):
    hmac_key = get_random_bytes(16)
    cipher = PKCS1_OAEP.new(public_RSA)
    hmac_encrypt = cipher.encrypt(hmac_key)

    hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    encrypted_data = b""
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if len(chunk) == 0:
                break
            hmac_obj.update(chunk)
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk, AES.block_size)
            encrypted_data += cipher_aes.encrypt(chunk)

    hmac_digest = hmac_obj.digest()
    
    return iv, encrypted_data, hmac_encrypt, hmac_digest

# Client function to connect and send files
def client(window, file_path):
    sock_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_client.connect(('localhost', 1002))
    window['-OUTPUT-'].print("Client B connected :")
    
    try:
        public_key = sock_client.recv(2048)
        window['-OUTPUT-'].print("\nReceived public RSA key.")
        aes_key = get_random_bytes(16)
        import_public = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(import_public)
        chiff = cipher.encrypt(aes_key)
        
        sock_client.sendall(chiff)
        window['-OUTPUT-'].print("\nAES encrypted key sent.")

        iv, encrypted_file, encrypted_hmac_key, hmac_digest = encrypt_file(import_public, aes_key, file_path)
        
        sock_client.sendall(encrypted_hmac_key)
        window['-OUTPUT-'].print("\nHMAC key sent.")
        sock_client.sendall(hmac_digest)
        window['-OUTPUT-'].print("\nHMAC digest sent.")
        sock_client.sendall(iv)
        sock_client.sendall(encrypted_file)
        window['-OUTPUT-'].print("\nFile sent.")
        
    except KeyboardInterrupt:
        window['-OUTPUT-'].print("Client stopped.")
    finally:
        sock_client.close()

# Graphical Interface
def main():
    layout = [
        [sg.Text("Choose an option:")],
        [sg.Button("Send a file"), sg.Button("Receive a file"), sg.Button("Exit")],
        [sg.Output(size=(80, 20), key='-OUTPUT-')],
        [sg.Text("File path to send:"), sg.Input(key='-FILE_PATH-'), sg.FileBrowse()]
    ]
    
    window = sg.Window("User A Interface", layout)
    
    while True:
        event, values = window.read()
        
        if event == sg.WINDOW_CLOSED or event == "Exit":
            break
        elif event == "Send a file":
            file_path = values['-FILE_PATH-']
            if file_path:
                client(window, file_path)
            else:
                sg.popup("Please select a file to send.")
        elif event == "Receive a file":
            threading.Thread(target=server, args=(window,), daemon=True).start()
    
    window.close()

if __name__ == "__main__":
    main()