################################################################################################################################################################
#IMPORTS
import random
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import symmetric_generate
import pgp_encrypt
import hashing
import sign
import csr
##############################################################################################################################################################
# Initialize and connect your client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))
##############################################################################################################################################################
# FOR GUI
#LOGIN FRAME
def login(username, password):
    request = f"login,{username},{password}"
    encrypted_creds = encrypt(request.encode("utf-8"))
    client_socket.send(encrypted_creds)

    response = client_socket.recv(1024).decode("utf-8")
    print(response)  # or handle the response in another way

    if response.startswith("Successful: Logged in as a doctor."):
        return "doctor"
    elif response.startswith("Successful: Logged in as a student."):
        return "student"
    else:
        return "failure"

#ADDITIONAL DATA FRAME
def send_student_info(phone_number, address):
    request = f"{phone_number},{address}"
    encrypted_info = encrypt(request.encode("utf-8"))
    client_socket.send(encrypted_info)
    response = client_socket.recv(1024).decode("utf-8")
    return response

#GRAD DATA FRAME
def send_project_title(project_title):
    pubkey = client_socket.recv(4096).decode("utf-8")
    print(pubkey)
    session_key,session_iv = symmetric_generate.generate_key_iv()
    str_session_key= str(session_key)
    str_session_iv= str(session_iv)
    encrypted_session_key = pgp_encrypt.encrypt(str_session_key.encode("utf-8"))
    client_socket.send(encrypted_session_key)
    

    encrypted_session_iv = pgp_encrypt.encrypt(str_session_iv.encode("utf-8"))
    client_socket.send(encrypted_session_iv)
    response = client_socket.recv(1024).decode("utf-8")
    print(response)

    # project_title = input("Enter the title of your graduation project: ")
    request= f"{project_title}"

    encrypted_title = encrypt(request.encode("utf-8"))
    client_socket.send(encrypted_title)
    

    # # Handle response for project title
    response = client_socket.recv(1024).decode("utf-8")
    print(response)
    return response

# Create Account Frame
def create_account(username, password, user_type):
    request = f"create,{username},{password},{user_type}"
    encrypted_request = encrypt(request.encode("utf-8"))
    client_socket.send(encrypted_request)

    response = client_socket.recv(1024).decode("utf-8")
    print(response)  # For debugging
    return response

# Generate Math Problem
def generate_math_problem():
    x = random.randint(1, 10)
    problem = f"Solve for x: {x}^2 = ?"
    return problem, x**2

# Verify Answer
def verify_math_answer(user_answer, correct_answer):
    if user_answer.isdigit() and int(user_answer) == correct_answer:
        return True
    else:
        return False
    
# # Generate CSR
# def generate(username):
#     csr.generate(username)     
    
##############################################################################################################################################################
# Manual key and IV
symmetric_key = b'%b\xe0s\x92\xa5\x1f\x84\xda\xc1\x8cm\x15\x08\xab/\xe4\x86\x8b?<\xd0\xf2?2\xd9\xf2q58\x1e\xc2'
symmetric_iv = b'\xce~\x82\xff\x86\tC*{\xa7K\xd5(?\x9e\xfa'

# Symmetrical Encryption and Decryption Based on Manual Key and IV ( Task 2 )

def encrypt(message):
    padder = padding.PKCS7(128).padder()  
    padded_data = padder.update(message) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv), backend=default_backend()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt(ciphertext):
    decryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()  
    return unpadder.update(decrypted_data) + unpadder.finalize()

# Generate key and IV
session_key = ''
session_iv = ''

def encryptt(message):
    padder = padding.PKCS7(128).padder()  
    padded_data = padder.update(message) + padder.finalize()
    encryptor = Cipher(algorithms.AES(session_key), modes.CBC(session_iv), backend=default_backend()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decryptt(ciphertext):
    decryptor = Cipher(algorithms.AES(session_key), modes.CBC(session_iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder() 
    return unpadder.update(decrypted_data) + unpadder.finalize()


##############################################################################################################################################################

# Public Key from Server
pubkey_server = ''

##############################################################################################################################################################
#MAIN FUNCTION

def main():
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect(('localhost', 12345))
    logged_in = False
    username = ''

##############################################################################################################################################################
#LOOP

    while True:
        if not logged_in:
            action = input("Enter 'create' to create an account, 'login' to log in, or 'exit' to quit: ")

            if action not in ['create', 'login', 'exit']:
                print("Invalid action. Please enter 'create', 'login', or 'exit'.")
                continue

            # EXIT 

            if action == 'exit':

                request = f"{action},{0},{0}"
                encrypted_exit = encrypt(request.encode("utf-8"))
                client_socket.send(encrypted_exit)     

                break

            # CREATE
            if action == 'create':

                username = input("Enter username: ").lower()
                password = input("Enter password: ")
                user_type = input("Enter user type (doctor/student): ").lower()

                request = f"{action},{username},{password},{user_type}"
                encrypted_creds = encrypt(request.encode("utf-8"))
                client_socket.send(encrypted_creds)

                response = client_socket.recv(1024).decode("utf-8")
                print(response)
                
            # LOGIN 
            if action == 'login':

                username = input("Enter username: ").lower()
                password = input("Enter password: ")
                
                request = f"{action},{username},{password}"
                encrypted_creds = encrypt(request.encode("utf-8"))
                client_socket.send(encrypted_creds)

                response = client_socket.recv(1024).decode("utf-8")
                print(response)

                if response.startswith("Successful: Logged in as a doctor."):
                    logged_in = True
                    user_type = 'doctor'
                elif response.startswith("Successful: Logged in as a student."):
                    logged_in = True
                    user_type = 'student'
                else:                    
                    continue

        else: 
            
            if user_type=='student':
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
                    pubkey = client_socket.recv(4096).decode("utf-8")
                    print(pubkey)
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
                    
                break
            else:
                result = csr.generate(username)
                if result.startswith("Successful: CSR verification and signing complete."):
                    project_grade = input("Enter the grade of the graduation project for team 10: ")

                    sessioned_grade = encrypt(project_grade.encode("utf-8"))
                    print('SESSIONED CLIENT GRADE:' ,sessioned_grade)
                    client_socket.send(sessioned_grade)

                    hashed_grade_client = hashing.sha256(project_grade)
                    print('HASHED:', hashed_grade_client)
                    signed_hashed_grade = sign.sign_data(hashed_grade_client,password)
                    print('SIGNED HASHED' , signed_hashed_grade)

                    request = f"{signed_hashed_grade}"
                    client_socket.send(request.encode("utf-8"))
                    break
                else:
                    print('Could not generate CSR')
                    break



    print("Closing socket.")    
    client_socket.close()

if __name__ == '__main__':
    main()
