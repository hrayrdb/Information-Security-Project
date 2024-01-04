import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
import datetime

bool = False

def receive_and_sign_csr(client_socket):
    # Receive the length of the CSR data
    csr_length = int.from_bytes(client_socket.recv(4), byteorder='big')

    # Receive the CSR data
    csr_data = client_socket.recv(csr_length)

    # Load CA private key and certificate
    with open("ca_private_key.pem", "rb") as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  #للتسهيل
            backend=default_backend()
        )

    with open("ca_certificate.pem", "rb") as cert_file:
            ca_certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        
    # Load client CSR
    client_csr = x509.load_pem_x509_csr(csr_data, default_backend())

    # Sign the client CSR
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(client_csr.subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(client_csr.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    client_certificate = builder.sign(ca_private_key, hashes.SHA256(), default_backend())

    # Save signed client certificate to a file (you might want to send it back to the client)
    with open("signed_client_certificate.pem", "wb") as f:
        f.write(client_certificate.public_bytes(serialization.Encoding.PEM))

    # Send a success response back to the client
    response = "Successful: CSR verification and signing complete."
    client_socket.send(response.encode("utf-8"))


    client_socket.close()

if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12346))  
    server_socket.listen(6)
    print("CA Server is listening...")

    client_socket, addr = server_socket.accept()
    print(f"Connection established with {addr}")


    receive_and_sign_csr(client_socket)

    server_socket.close()
