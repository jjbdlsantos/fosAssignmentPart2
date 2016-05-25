import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

decryption_key_file = 'decryption_key.txt'
# TODO: Get a better password
password = "testtest"

def decrypt_valuables(f):
    decryption_key = get_decryption_key_from_file()
    decode_cipher = PKCS1_v1_5.new(decryption_key)
    decoded_text = decode_cipher.decrypt(f, "Error")
    print("Decoded text: {}".format(decoded_text))

def get_decryption_key_from_file():
    file = open(decryption_key_file, 'rb')
    encrypted_key = file.read()
    file.close()
    decryption_key = RSA.importKey(encrypted_key, passphrase=password)
    #print("Private key read: {}".format(decryption_key.exportKey()))
    return decryption_key

def generate_key_pair():
    key = RSA.generate(4096)

    public_key = key.publickey()
    public_key = public_key.exportKey()
    print("Public Key: {}".format(public_key))

    encrypted_private_key = key.exportKey(passphrase=password, pkcs=8)
    file_out = open(decryption_key_file, "wb")
    file_out.write(encrypted_private_key)
    print("Private key: {}".format(key.exportKey()))


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)

