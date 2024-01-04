import gnupg

def decrypt(dataa):
    # print('STARTED DECRYPTING')
    gpg = gnupg.GPG()
    decrypted = gpg.decrypt(dataa,passphrase = '@server0')
    # print('DONE DECRYPTING', decrypted)
    return decrypted.data


if __name__ == '__main__':
    decrypt()