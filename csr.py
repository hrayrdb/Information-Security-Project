from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import connect_ca

def generate(name):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
    ).sign(private_key, hashes.SHA256(), default_backend())

    print(csr)

    with open(f"{name}_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return connect_ca.main(name)


