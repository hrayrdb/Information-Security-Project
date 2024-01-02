from pgpy import PGPKey, PGPUID
import pgpy

# Generate a new RSA key pair
# key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
# Create a new user ID
uid = PGPUID.new('Your Name', email='your.email@example.com')

# Bind the UID to the key
key.add_uid(uid, usage={'S', 'E'}, hashes=['SHA256'], ciphers=['AES256'])

# Save the private key to a file
with open('server_private_key.asc', 'w') as f:
    f.write(str(key))

# Save the public key to a file
with open('server_public_key.asc', 'w') as f:
    f.write(str(key.pubkey))


