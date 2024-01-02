import gnupg

def encrypt(dataa):
    # print('STARTED ENCRYPTING')
    gpg = gnupg.GPG()
    encrypted = gpg.encrypt(data = dataa , recipients=['hrayr'])
    # print('DONE ENCRYPTING',encrypted)
    return encrypted.data


if __name__ == '__main__':
    encrypt()