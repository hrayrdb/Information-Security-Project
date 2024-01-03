import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import symmetric_generate
import pgp_encrypt
import hashing
import sign

# Manual key and IV
symmetric_key = b'%b\xe0s\x92\xa5\x1f\x84\xda\xc1\x8cm\x15\x08\xab/\xe4\x86\x8b?<\xd0\xf2?2\xd9\xf2q58\x1e\xc2'
symmetric_iv = b'\xce~\x82\xff\x86\tC*{\xa7K\xd5(?\x9e\xfa'

# Public Key from Server
pubkey_server = ''

# Generate key and IV
session_key = ''
session_iv = ''

def encrypt(message):
    padder = padding.PKCS7(128).padder()  # 128-bit padding for AES
    padded_data = padder.update(message) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv), backend=default_backend()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt(ciphertext):
    decryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv), backend=default_backend()).decryptor()
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
                pubkey_server = client_socket.recv(4096).decode("utf-8")
                print(pubkey_server)
                session_key,session_iv = symmetric_generate.generate_key_iv()
                str_session_key= str(session_key)
                str_session_iv= str(session_iv)
                encrypted_session_key = pgp_encrypt.encrypt(str_session_key.encode("utf-8"))
                client_socket.send(encrypted_session_key)
                

                encrypted_session_iv = pgp_encrypt.encrypt(str_session_iv.encode("utf-8"))
                client_socket.send(encrypted_session_iv)
                response = client_socket.recv(1024).decode("utf-8")
                print(response)

                project_title = input("Enter the title of your graduation project: ")
                request= f"{project_title}"

                encrypted_title = encrypt(request.encode("utf-8"))
                client_socket.send(encrypted_title)
                print("Sent encrypted project title.")

                # Handle response for project title
                response = client_socket.recv(1024).decode("utf-8")
                print(response)

                project_grade = input("Enter the grade of your graduation project: ")

                sessioned_grade = encrypt(project_grade.encode("utf-8"))
                print('SESSIONED CLIENT GRADE:' ,sessioned_grade)
                client_socket.send(sessioned_grade)

                hashed_grade_client = hashing.sha256(project_grade)
                signed_hashed_grade = sign.sign_data(hashed_grade_client)
                print('SIGNED HASHED' , signed_hashed_grade)

                request = f"{signed_hashed_grade}"
                client_socket.send(request.encode("utf-8"))


            break
        
    print("Closing socket.")    
    client_socket.close()

if __name__ == '__main__':
    main()
