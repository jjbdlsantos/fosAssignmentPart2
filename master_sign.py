import os

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5

# Name of the file where the signing key is stored
signing_key_file = 'signing_key.txt'
# TODO: Get a better password
password = "testtest"

def sign_file(file):
    print("file: {}".format(file))

    # TODO: For Part 2, you'll use public key crypto here

    signing_key = get_signing_key_from_file()
    sig_scheme = PKCS1_v1_5.new(signing_key)

    # Hash the message to compress it to 128 bits before signing
    # Hashing ensures that RSA will be able to sign/encrypt the message
    # (limitation of RSA is that m must be less than n)
    hashed_file = MD5.new(file)
    signature = sig_scheme.sign(hashed_file)
    #print("Signature: {}".format(signature))

    # Separate the signature and the file contents with three newline characters
    # Ensures that the 'separation string' can't be found within the signature
    return signature + bytes("\n\n\n", "ascii") + file


def get_signing_key_from_file():
    # Open file and read the encrypted key
    file_in = open(signing_key_file, 'rb')
    # Get the key, using the password to decrypt it
    signing_key = RSA.importKey(file_in.read(), passphrase=password)
    #print("Private key read: {}".format(signing_key.exportKey()))
    file_in.close()
    return signing_key

def generate_signing_and_verifying_keys():
    # Generate 4096-bit public and private keys
    key = RSA.generate(4096)

    # Export the public key
    public_key = key.publickey()
    public_key = public_key.exportKey()
    print("Public Key: {}".format(public_key))

    # Encrypt and export the private key
    encrypted_private_key = key.exportKey(passphrase=password, pkcs=8)
    # Write the private key to file
    file_out = open(signing_key_file, "wb")
    file_out.write(encrypted_private_key)
    file_out.close()
    print("Private key: {}".format(key.exportKey()))


if __name__ == "__main__":
    # generate_signing_and_verifying_keys()
    # get_signing_key_from_file()
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)

