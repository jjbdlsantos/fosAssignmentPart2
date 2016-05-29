import os

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

password = "dflgkhdfkjghdjfhgd;"

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

    # TODO: hash f?
    # TODO: Don't use PKCS #1 alone, because limitation of RSA: m < n
    signing_key = read_signing_key_from_file()
    signing_object = PKCS1_v1_5.new(signing_key)
    signature = signing_object.sign(f)
    print(signature)
    return bytes(signature, "ascii") + f


def read_signing_key_from_file(self):
    # TODO: Private key is saved in a file; read & unhash it (?)
    file = open('signing_key.txt', 'r')
    #signing_key = file.read()
    signing_key = RSA.importkey(file.read(), passphrase = password)
    file.close()
    return signing_key

def generate_signing_verifying_key():
    key = RSA.generate(4096)
    # Export the public key - now it's an RSA object so exporting it makes it a string
    public_key = key.publickey()
    public_key = public_key.exportKey()
    print("Public Key: {}".format(public_key))

    # Encrypt and export the private key
    encrypted_private_key = key.exportKey(passphrase=password, pkcs=8)
    # Write the private key to file
    file_out = open('signing_key.txt', "wb")
    file_out.write(encrypted_private_key)
    file_out.close
    print("Private key: {}".format(key.exportKey()))

if __name__ == "__main__":
    generate_signing_verifying_key()
    # fn = input("Which file in pastebot.net should be signed? ")
    # if not os.path.exists(os.path.join("pastebot.net", fn)):
    #     print("The given file doesn't exist on pastebot.net")
    #     os.exit(1)
    # f = open(os.path.join("pastebot.net", fn), "rb").read()
    # signed_f = sign_file(f)
    # signed_fn = os.path.join("pastebot.net", fn + ".signed")
    # out = open(signed_fn, "wb")
    # out.write(signed_f)
    # out.close()
    # print("Signed file written to", signed_fn)