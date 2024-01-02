import os

def generate_key_iv():
    print('STARTED GENERATING SESSION KEY')
    key = os.urandom(32)
    iv = os.urandom(16) 
    print(key)
    print(iv)
    return key,iv


if __name__ == '__main__':
    generate_key_iv()