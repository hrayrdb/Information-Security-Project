################################################################################################################################################################
#IMPORTS

import os
import socket
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import pgp_generate
import pgp_decrypt
import gnupg
import sign
import hashing
import mysql.connector
from mysql.connector import Error
from cryptography import x509
from cryptography.hazmat.backends import default_backend
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



# Will be used to store Session Key and IV from the client
session_key=''
session_iv=''

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
#DATABASE

# MySQL Connection Function
def create_database_connection():
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',  # Or your MySQL server host
            database='issproject',
            user='root',
            password=''
        )
        return connection
    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None


# Add User to Database
def add_user_to_database(username, password, user_type, connection):
    try:
        cursor = connection.cursor()
        query = "INSERT INTO users (username, password, user_type) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, password, user_type))
        connection.commit()
        cursor.close()
    except Error as e:
        print(f"Error while adding user to MySQL: {e}")


# Validate User Login
def validate_user_login(username, password, connection):
    try:
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    except Error as e:
        print(f"Error while validating user login: {e}")
        return False
    

 #Update User Details   
def update_user_details(username, phone_number, address, connection):
    try:
        cursor = connection.cursor()
        query = """
        UPDATE users SET phone_number = %s, address = %s
        WHERE username = %s
        """
        cursor.execute(query, (phone_number, address, username))
        connection.commit()
        cursor.close()
    except Error as e:
        print(f"Error while updating user details in MySQL: {e}")


#Update Project title
def update_project_title(username, project_title, connection):
    try:
        cursor = connection.cursor()
        query = "UPDATE users SET project_title = %s WHERE username = %s"
        cursor.execute(query, (project_title, username))
        connection.commit()
        cursor.close()
    except Error as e:
        print(f"Error while updating project title in MySQL: {e}")
        
#Update Public Key
def update_public_key(username, public_key, connection):
    try:
        cursor = connection.cursor()
        query = "UPDATE users SET public_key = %s WHERE username = %s"
        cursor.execute(query, (public_key, username))
        connection.commit()
        cursor.close()
    except Error as e:
        print(f"Error while updating public key in MySQL: {e}")

# Check username exists in database
def does_username_exist(username, connection):
    try:
        cursor = connection.cursor()
        query = "SELECT COUNT(*) FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        (count,) = cursor.fetchone()
        cursor.close()
        return count > 0
    except Error as e:
        print(f"Error while checking username existence in MySQL: {e}")
        return False


# Get User Type    
def get_user_type(username, connection):
    try:
        cursor = connection.cursor()
        query = "SELECT user_type FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        if result:
            return result[0]  # Return the user_type
        else:
            return None  # User not found or no user_type
    except Error as e:
        print(f"Error while retrieving user type from MySQL: {e}")
        return None

##############################################################################################################################################################
#VALIDATION


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

##############################################################################################################################################################

gpg = gnupg.GPG()  

##############################################################################################################################################################
#MAIN FUNCTION

def main():

    #Init Server Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server is listening...")

    #Establish Connection with Database
    connection = create_database_connection()


    #Generate Public Key for Client
    pubkey = pgp_generate.generate_key()



    while True:

        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        while True:

            request_encrypted = client_socket.recv(1024)
            
            if not request_encrypted:
                print("No data received. Closing connection.")
                break
            
            if request_encrypted == b'':
                continue

            request = decrypt(request_encrypted).decode("utf-8")
            request_parts = request.split(',')
            action = request_parts[0]


            if len(request_parts) > 1:
                username = request_parts[1]
            else:
                username = None

##############################################################################################################################################################
#Create
                
            if action == 'create':
                if len(request_parts) >= 4:
                    username, password, user_type = request_parts[1:4]

                    # Validate 
                    if does_username_exist(username, connection):
                        response = "Failed: Username already exists."        

                    elif user_type not in ['doctor', 'student']:
                        response = "Failed: Invalid user type."

                    elif not is_valid_password(request_parts[2]):
                        response = "Failed: Password does not meet criteria."

                    else:
                        add_user_to_database(username, password, user_type, connection)
                        response = "Successful: Account created."
                else:
                    response = "Failed: Invalid data."
                                        
                client_socket.send(response.encode("utf-8"))
                print(f"Create Action Done for {username}")

##############################################################################################################################################################       
#Login 
                
            if action == 'login':
                if len(request_parts) >= 3:
                    username, password = request_parts[1:3]
                    if validate_user_login(username, password, connection):
                        user_type = get_user_type(username, connection)
                        if user_type == 'doctor':
                            response = "Successful: Logged in as a doctor."
                        elif user_type == 'student':
                            response = "Successful: Logged in as a student."                     
                        print(response)
                        client_socket.send(response.encode("utf-8"))
                        print(f"Login action processed for {username}")

       
                    #STUDENT
                    if 'Successful: Logged in as a student.' in response:
                        additional_info_encrypted = client_socket.recv(1024)
                        additional_info = decrypt(additional_info_encrypted).decode("utf-8")
                        print(f"Received additional info for {username}: {additional_info}")
                        phone_number, address = additional_info.split(',',1)
                        update_user_details(username, phone_number, address, connection)
                        

                        response = "Successful: Additional information added."
                        client_socket.send(response.encode("utf-8"))


                        public_key_data = str(pubkey)
                        update_public_key(username,public_key_data,connection)
                        encoded_pubkey = public_key_data.encode("utf-8")
                        client_socket.send(encoded_pubkey)
                        print(f"Public key sent to client {username}")   

                        encrypted_session_key = client_socket.recv(1024)
                        decrypted_session_key = pgp_decrypt.decrypt(encrypted_session_key)
                        session_key=decrypted_session_key.decode("utf-8")

                        encrypted_session_iv = client_socket.recv(1024)
                        decrypted_session_iv = pgp_decrypt.decrypt(encrypted_session_iv)
                        session_iv=decrypted_session_iv.decode("utf-8")

                        response = "Session Key Stored."
                        client_socket.send(response.encode("utf-8"))

                        print("Waiting for project title...")
                        encrypted_project_title = client_socket.recv(1024)
                        decrypted_project_title = decrypt(encrypted_project_title).decode("utf-8")
                        print('DECRYPTED PROJECT TITLE:' , decrypted_project_title)
                        update_project_title(username,decrypted_project_title,connection)

                        response = "Successful: Project title received."

               
                    else:
                        certificate_file = "signed_client_certificate.pem"

                        if os.path.exists(certificate_file):
                            with open(certificate_file, "rb") as f:
                                certificate_data = f.read()
                                certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())


                                subject_dn = certificate.subject


                                common_name_attr = subject_dn.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

                                # Check if attributes are present before accessing their values
                                common_name = common_name_attr[0].value if common_name_attr else None

                                print("Common Name (CN):", common_name)

                                if common_name == username:
                                    public_key_data = str(pubkey)
                                    update_public_key(username,public_key_data,connection)
                                    print('Doctor Verified, Waiting for Project Grade: ')
                                    sessioned_grade = client_socket.recv(1024)
                                    decrypted_grade = decrypt(sessioned_grade).decode("utf-8")
                                    print("DECRYPTED GRADE:" , decrypted_grade)

                                    hashed_grade_server = hashing.sha256(decrypted_grade)
                                    print('HASHED GRADE FROM SERVER:' , hashed_grade_server)

                                    signed_hashed_grade = client_socket.recv(1024).decode('utf-8')
                                    print('SIGNED HASHED GRADE CLIENT:',signed_hashed_grade)

                                    verification = sign.verify_data(signed_hashed_grade)
                                    if verification:
                                        unsigned_hashed_grade = pgp_decrypt.decrypt(signed_hashed_grade).decode('utf-8')
                                        if unsigned_hashed_grade.strip() == hashed_grade_server.strip():        
                                            print('DATA INTEGRITY TRUE, SYSTEM IS SECURE')
                                            break
                                    else:
                                        print('NO DATA INTEGRITY')
                                        break

                        else:
                            print("Certificate file does not exist, you can't continue")
                            break

                        
                    client_socket.send(response.encode("utf-8"))
                    print(response)
                

#######################################################################################################################################################################
            #Exit
                    
            if action == 'exit':
                client_socket.close()
                print(f"Socket to client {addr} closed.")
                break

        
        #Close the socket 

        client_socket.close()
        print("Client socket closed.")

        # if connection:
        #     print("Connection closed.")
        #     connection.close()                   
                
                
##############################################################################################################################################################                   
#When Run
        
if __name__ == '__main__':
    main()
