import os

from Crypto.PublicKey import RSA
from Crypto import Random

def decrypt_valuables(f):
    decryption_key = get_decryption_key_from_file()
    decoded_text = decryption_key.decrypt(f)
    print(decoded_text)

def get_decryption_key_from_file():
    # TODO: Private key is saved in a file; read it and use it
    key_read = 'test'

    decryption_key = RSA.importKey(key_read)
    return decryption_key

def generate_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(4096, random_generator)
    public_key = key.publickey()
    public_key = public_key.exportKey()
    print("Public Key: {}".format(public_key))

    private_key = key.exportKey()
    print("Private Key: {}".format(private_key))


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)

