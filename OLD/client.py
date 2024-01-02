import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import gnupg
import os

# Manual key and IV
key = b'%b\xe0s\x92\xa5\x1f\x84\xda\xc1\x8cm\x15\x08\xab/\xe4\x86\x8b?<\xd0\xf2?2\xd9\xf2q58\x1e\xc2'
iv = b'\xce~\x82\xff\x86\tC*{\xa7K\xd5(?\x9e\xfa'


def encrypt(message):
    padder = padding.PKCS7(128).padder()  # 128-bit padding for AES
    padded_data = padder.update(message) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt(ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()  # 128-bit padding for AES
    return unpadder.update(decrypted_data) + unpadder.finalize()

########### Third Stage ##############
def generate_pgp_keys(name, email, passphrase):
    gpg = gnupg.GPG(gnupghome= r'C:\Users\maria\OneDrive\Desktop\Information-Security-Project\gnupg_data', gpgbinary=r'C:\Program Files (x86)\GnuPG\bin\gpg.exe')
    input_data = gpg.gen_key_input(
        name_real=name,
        name_email=email,
        passphrase=passphrase
    )
    key = gpg.gen_key(input_data)
    return key

def export_keys(gpg, key, passphrase):
    private_key = gpg.export_keys(key.fingerprint, secret=True, passphrase=passphrase)
    public_key = gpg.export_keys(key.fingerprint)
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'w') as file:
        file.write(key)
        
def setup_pgp():
    gpg_home = r'C:\Users\maria\OneDrive\Desktop\Information-Security-Project\gnupg_data'
    gpg_binary = r'C:\Program Files (x86)\GnuPG\bin\gpg.exe'  # Update this path as needed
    if not os.path.isdir(gpg_home):
        os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home, gpgbinary=gpg_binary)

    # Check if the keys exist, generate if they don't
    if not os.path.exists(os.path.join(gpg_home, 'private_key.asc')) or \
       not os.path.exists(os.path.join(gpg_home, 'public_key.asc')):
        key = generate_pgp_keys('Your Name', 'your.email@example.com', 'your-secure-passphrase')
        private_key, public_key = export_keys(gpg, key, 'your-secure-passphrase')
        save_key_to_file(private_key, os.path.join(gpg_home, 'private_key.asc'))
        save_key_to_file(public_key, os.path.join(gpg_home, 'public_key.asc'))

    return gpg
#################################################

def main():
    # Set up PGP
    gpg = setup_pgp()
    gpg_home = r'C:\Users\maria\OneDrive\Desktop\Information-Security-Project\gnupg_data'

    #######################################################
    # Import private key (for decryption)
    with open(os.path.join(gpg_home, 'private_key.asc'), 'rb') as f:
        private_key = f.read()
    gpg.import_keys(private_key)

    # Import public key (for encryption)
    with open(os.path.join(gpg_home, 'public_key.asc'), 'rb') as f:
        public_key = f.read()
    gpg.import_keys(public_key)
    
    ######################################################
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    logged_in = False
    username = ''

    while True:
        if not logged_in:
            action = input("Enter 'create' to create an account, 'login' to log in, or 'exit' to quit: ")

            if action not in ['create', 'login', 'exit']:
                print("Invalid action. Please enter 'create', 'login', or 'exit'.")
                continue

            if action == 'exit':
                request = f"{action},{0},{0}"
                encrypted_exit = encrypt(request.encode("utf-8"))

                client_socket.send(encrypted_exit)                
                break

            username = input("Enter username: ").lower()
            password = input("Enter password: ")
            
            request = f"{action},{username},{password}"
            encrypted_creds = encrypt(request.encode("utf-8"))

            client_socket.send(encrypted_creds)
            response = client_socket.recv(1024).decode("utf-8")

            print(response)

            if response.startswith("Successful: Login"):
                logged_in = True
            else:
                continue

        else:
            phone_number = input("Enter phone number: ")
            address = input("Enter address: ")

             # Send phone number and address first
            request = f"{phone_number},{address}"
            encrypted_info = encrypt(request.encode("utf-8"))
            client_socket.send(encrypted_info)
            
             # Get response and ask for project title
            response = client_socket.recv(1024).decode("utf-8")
            print(response)

            if response.startswith("Successful"):
                project_title = input("Enter the title of your graduation project: ")
                encryption_result = gpg.encrypt(project_title, recipients='actual-server-public-key-id')
                if not encryption_result.ok:
                    print(f"Encryption failed: {encryption_result.status}")
                    return

                encrypted_project_title = str(encryption_result).encode('utf-8')

                client_socket.send(encrypted_project_title)
                print(f"Sent encrypted project title: {encrypted_project_title}")

                # Handle response for project title
                response = client_socket.recv(1024).decode("utf-8")
                print(response)
                
            break
        
    print("Closing socket.")    
    client_socket.close()

if __name__ == '__main__':
    main()
