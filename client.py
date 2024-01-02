import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import gnupg

# Manual key and IV
key = b'%b\xe0s\x92\xa5\x1f\x84\xda\xc1\x8cm\x15\x08\xab/\xe4\x86\x8b?<\xd0\xf2?2\xd9\xf2q58\x1e\xc2'
iv = b'\xce~\x82\xff\x86\tC*{\xa7K\xd5(?\x9e\xfa'


gpg = gnupg.GPG()
input_data = gpg.gen_key_input(key_type="RSA", key_length=2048)
key = gpg.gen_key(input_data)
public_key = key.fingerprint
print(public_key)
private_key = key.keymaterial.decode()



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

def main():
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
                # encrypted_message = public_key.encrypt(PGPMessage.new(project_title))
                # client_socket.send(bytes(str(encrypted_message), 'utf-8'))
                print("Sent encrypted project title.")

                # Handle response for project title
                response = client_socket.recv(1024).decode("utf-8")
                print(response)
                
            break
        
    print("Closing socket.")    
    client_socket.close()

if __name__ == '__main__':
    main()
