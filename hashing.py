import hashlib


def sha256(dataa):
    # print('STARTED HASHING')
    hsh = hashlib.sha256()
    hsh.update(dataa.encode('utf-8'))
    hashed = hsh.hexdigest()
    # print('DONE HASHING', hashed)
    return hashed


if __name__ == '__main__':
    sha256()