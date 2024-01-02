import os
import socket
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import gnupg

# Manual key and IV
key = b'%b\xe0s\x92\xa5\x1f\x84\xda\xc1\x8cm\x15\x08\xab/\xe4\x86\x8b?<\xd0\xf2?2\xd9\xf2q58\x1e\xc2'
iv = b'\xce~\x82\xff\x86\tC*{\xa7K\xd5(?\x9e\xfa'


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()_+]", password):
        return False
    return True

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
    gpg = gnupg.GPG()
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
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server is listening...")
    accounts = {}

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")
        while True:

            request_encrypted = client_socket.recv(1024)
            
            #
            if not request_encrypted:
                print("No data received. Closing connection.")
                break
            
            
            if request_encrypted == b'':
                continue
            
            print(f"ENCRYPTED REQUEST: {request_encrypted}")
            request = decrypt(request_encrypted).decode("utf-8")
            print(f"DECRYPTED REQUEST: {request}")
            
            request_parts = request.split(',')
            action = request_parts[0]

            # if action == 'exit':
            #     client_socket.close()
            #     print("Socket to client closed.")
            #     break

            if len(request_parts) > 1:
                username = request_parts[1]
            else:
                username = None

            if action == 'create' and username is not None:
                if username in accounts:
                    response = "Failed: Username already exists."
                elif not is_valid_password(request_parts[2]):
                    response = "Failed: Password does not meet criteria."
                else:
                    accounts[username] = {'password': request_parts[2]}
                    response = "Successful: Account created."
                client_socket.send(response.encode("utf-8"))
                print(f"Create action processed for {username}")
                
            elif action == 'login' and username is not None:
                if accounts.get(username, {}).get('password') == request_parts[2]:
                    response = "Successful: Login."
                    client_socket.send(response.encode("utf-8"))
                    print(f"Login action processed for {username}")
                    
                    # If login successful, handle additional information
                    if 'Successful: Login' in response:
                        additional_info_encrypted = client_socket.recv(1024)
                        additional_info = decrypt(additional_info_encrypted).decode("utf-8")
                        print(f"Received additional info: {additional_info}")
                        phone_number, address = additional_info.split(',',1)
                        accounts[username].update({'phone_number': phone_number, 'address': address})
                        
                        # Send response for additional info
                        response = "Successful: Additional information added."
                        #print(accounts[username])
                        client_socket.send(response.encode("utf-8"))
                        print("Response sent for additional information.")
                        print("Waiting for project title...")
                        
                        ####################################################
                        # Receive and decrypt project title
                        encrypted_project_title = client_socket.recv(1024)
                        project_title = str(gpg.decrypt(encrypted_project_title, passphrase='server-secure-passphrase'))
                        print(f"Decrypted project title: {project_title}")

                        accounts[username]['project_title'] = project_title
                        response = "Successful: Project title received."
                        client_socket.send(response.encode("utf-8"))
                        print("Response sent for project title.")
                        ####################################################
                # else:
                #     response = "Failed: Invalid credentials."
                #     client_socket.send(response.encode("utf-8"))
                
            # Handle 'exit' action
            if action == 'exit':
                client_socket.close()
                print(f"Socket to client {addr} closed.")
                break

        client_socket.close()
        print("Client socket closed.")
                
                
                
                    

if __name__ == '__main__':
    main()
