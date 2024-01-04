import random
import socket

bool = False 

def verify_identity():
    # Generate a simple math problem
    x = random.randint(1, 10)
    problem = f"Solve for x: {x}^2 = ?"

    # Send the math problem to the client
    print(f"Math problem: {problem}")

    # Get the user's answer
    user_answer = input("Your answer: ")

    # Check if the answer is correct
    correct_answer = x ** 2
    if user_answer.isdigit() and int(user_answer) == correct_answer:
        print("Correct answer! Identity verified.")
        bool = True
        return bool
    else:
        print("Incorrect answer. Identity verification failed.")
        return bool


def send_csr_to_ca(csr_filename, ca_host, ca_port):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ca_host, ca_port))

        with open(csr_filename, "rb") as csr_file:
            csr_data = csr_file.read()

        # Send the length of the CSR data first
        csr_length = len(csr_data).to_bytes(4, byteorder='big')
        client_socket.send(csr_length)

        client_socket.send(csr_data)

        response = client_socket.recv(1024).decode("utf-8")
        print(response)
        return response

def main(name):
    csr_filename = f"{name}_csr.pem"  
    ca_host = "localhost" 
    ca_port = 12346

    bool = verify_identity()
    print(bool)
    
    if bool:
       return send_csr_to_ca(csr_filename, ca_host, ca_port)
    else:
        print('CAN NOT ACCESS')

