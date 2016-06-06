import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES

# Name of the file where the decryption key is stored
decryption_key_file = 'decryption_key.txt'
# Password used to decrypt the private key file
password = "W2[3Gfs-*ug#ABfkGWos1{x8:!d5R?+`]37}-rQU7AJ|ci[YEck1$e]DT;<S9K|q"

def decrypt_valuables(f):
    rsa_decryption_key = get_decryption_key_from_file()
    rsa_cipher = PKCS1_v1_5.new(rsa_decryption_key)

    # Encrypted session key will be the same length as the RSA keys (4096 bits = 512 bytes)
    session_key_len = 512
    session_key_and_iv_len = session_key_len + AES.block_size

    # Separate the different components in the encrypted data
    encrypted_session_key = f[:session_key_len]
    iv = f[session_key_len:session_key_and_iv_len]
    ciphertext = f[session_key_and_iv_len:]

    # Decrypt the session key, or assign "Error" if it fails
    session_key = rsa_cipher.decrypt(encrypted_session_key, "Error")

    # Decrypt the message using AES and the session key
    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv)
    decoded_text = aes_cipher.decrypt(ciphertext)
    print(str(decoded_text, "ascii"))


def get_decryption_key_from_file():
    # Open file and read the encrypted key
    file_in = open(decryption_key_file, 'rb')
    # Get the key, using the password to decrypt it
    decryption_key = RSA.importKey(file_in.read(), passphrase=password)
    file_in.close()
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
    file_out.close()
    print("Private key: {}".format(key.exportKey()))


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)

