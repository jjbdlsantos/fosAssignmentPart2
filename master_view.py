import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Name of the file where the decryption key is stored
decryption_key_file = 'decryption_key.txt'
# TODO: Get a better password
password = "testtest"

def decrypt_valuables(f):
    decryption_key = get_decryption_key_from_file()
    cipher_obj = PKCS1_v1_5.new(decryption_key)
    # Decode the ciphertext, and return 'error' if it fails
    decoded_text = cipher_obj.decrypt(f, "Error")
    print(str(decoded_text, "ascii"))

def get_decryption_key_from_file():
    # Open file and read the encrypted key
    file_in = open(decryption_key_file, 'rb')
    encrypted_key = file_in.read()
    file_in.close()

    # Get the key, using the password to decrypt it
    decryption_key = RSA.importKey(encrypted_key, passphrase=password)
    #print("Private key read: {}".format(decryption_key.exportKey()))
    return decryption_key

def generate_encryption_keys():
    # Generate 4096-bit public and private keys
    key = RSA.generate(4096)

    # Export the public key
    public_key = key.publickey()
    public_key = public_key.exportKey()
    print("Public Key: {}".format(public_key))

    # Encrypt and export the private key
    encrypted_private_key = key.exportKey(passphrase=password, pkcs=8)
    # Write the private key to file
    file_out = open(decryption_key_file, "wb")
    file_out.write(encrypted_private_key)
    file_out.close
    print("Private key: {}".format(key.exportKey()))


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)

