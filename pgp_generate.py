import gnupg


def generate_key():
    # print('STARTED GENERATING')
    gpg = gnupg.GPG()
    gpg.encoding = 'utf-8'
    input_data = gpg.gen_key_input(name_email = 'hrayr', passphrase = 'Hrayr@server0', key_type="RSA", key_length=2048)
    key = gpg.gen_key(input_data)
    # print('key:', key)
    return key



if __name__ == '__main__':
    generate_key()