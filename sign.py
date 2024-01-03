import gnupg
import time

gpg = gnupg.GPG()
gpg.encoding = 'utf-8'
fp = gpg.list_keys(True).fingerprints[0]


def sign_data(data):

    signed_data = gpg.sign(data, keyid=fp, passphrase='passphrase')
    if signed_data.fingerprint:
        print('Data signed successfully.')
        return signed_data
    else:
        print('Failed to sign the data.')
        return None

def verify_data(signed_data):

    verification_result = gpg.verify(signed_data)

    return verification_result.valid

