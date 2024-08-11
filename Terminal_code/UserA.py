import socket
import threading
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BUFFER_SIZE = 4096

# Function to generate RSA keys
def genererate_rsa_keys():
    mykey = RSA.generate(2048)
    public = mykey.public_key().export_key()
    pv = mykey.export_key()
    
    with open('publicA.pem', 'wb') as f:
        f.write(public)
    with open('priveA.pem', 'wb') as f:
        f.write(pv)
    
    return public

# Function to decrypt AES key with RSA private key
def decrypt_key_aes(chiff_aes):
    with open('priveA.pem', 'rb') as f:
        import_prive = RSA.import_key(f.read())
    
    cipher = PKCS1_OAEP.new(import_prive)
    decrypted_key = cipher.decrypt(chiff_aes)
    return decrypted_key

def decrypt_hmac_key(hmac_key) :
    with open('priveA.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_hmac_key = cipher.decrypt(hmac_key)
    return decrypted_hmac_key

# Function to receive and decrypt the file
def receive_file(sock_client, dechiff, decrypt_hmac, hmac_received):
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
    
    with open('received_text_A.txt', 'wb') as f:
        f.write(decrypted_data)

    hmac_obj = HMAC.new(decrypt_hmac, digestmod=SHA256)
    hmac_obj.update(decrypted_data)
    
    try:
        hmac_obj.verify(hmac_received)
        print("\nFile decrypted and authenticated successfully.")
    except ValueError:
        print("\nThe file has been modified or is corrupted.")
    

# Server function to listen and receive files
def server():
    public = genererate_rsa_keys()
    
    sock_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_serveur.bind(('localhost', 1000))
    sock_serveur.listen(20)
    print("User A listening on port 1000...")
    
    try:
        sock_client, add_client = sock_serveur.accept()
        print("Client connected : ", add_client)
        
        sock_client.sendall(public)
        print("\nPublic key sent.")
        
        chiff_aes = sock_client.recv(256)
        dechiff = decrypt_key_aes(chiff_aes)
        print("\nDecrypted AES key : ", dechiff)

        hmac_key = sock_client.recv(256)
        print("\nHmac_key received.")
        decrypt_hmac = decrypt_hmac_key(hmac_key)

        hmac_received = sock_client.recv(32)

        receive_file(sock_client, dechiff, decrypt_hmac, hmac_received)
        
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        sock_serveur.close()

# Function to encrypt and send the file
def encrypt_file(public_RSA, cle_aes, file_path):

    # Generate and encrypt the HMAC key
    hmac_key = get_random_bytes(16)
    cipher = PKCS1_OAEP.new(public_RSA)
    hmac_encrypt = cipher.encrypt(hmac_key)

    # Create HMAC object with the generated key
    hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)

    # Encrypt the file
    cipher_aes = AES.new(cle_aes, AES.MODE_CBC)
    iv = cipher_aes.iv
    encrypted_data = b""
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if len(chunk) == 0:
                break
            hmac_obj.update(chunk)      # Update HMAC with each chunk of the file
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk, AES.block_size)
            encrypted_data += cipher_aes.encrypt(chunk)

    # HMAC digest in hexadecimal format
    final_obj = hmac_obj.digest()
    
    return iv, encrypted_data, hmac_encrypt, final_obj

# Client function to connect and send files
def client():
    sock_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_client.connect(('localhost', 1002))
    print("Client A connected : ")
    
    try:
        export_public = sock_client.recv(2048)
        print("\nPublic RSA key received.")

        cle_aes = get_random_bytes(16)
        import_public = RSA.import_key(export_public)
        cipher = PKCS1_OAEP.new(import_public)
        chiff = cipher.encrypt(cle_aes)
        
        sock_client.sendall(chiff)
        print("\nAES encrypted key sent.")

        file_path = input("\nSpecify the path of the file to send: ")
        iv, encrypted_file, encrypted_hmac_key, final_obj = encrypt_file(import_public, cle_aes, file_path)
        
        sock_client.sendall(encrypted_hmac_key)
        print("\nHmac_key sent.")
        sock_client.sendall(final_obj)
        print("\nHmac_digite sent.")
        sock_client.sendall(iv)
        sock_client.sendall(encrypted_file)
        print("\nFile sent.")
        
    except KeyboardInterrupt:
        print("Client stopped.")
    finally:
        sock_client.close()

# Main menu to choose action
def __main__():
    while True:
        print("1: Send a file")
        print("2: Receive a file")
        print("3: Exit")
        choice = input("Choose an option ")
        if choice == "1":
            client()
        elif choice == "2":
            server()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

__main__()