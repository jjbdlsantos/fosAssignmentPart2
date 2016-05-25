import os

from Crypto.PublicKey import RSA


def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    decoded_text = str(f, 'ascii')

    # 4096 bit keys for RSA
    print(decoded_text)

def read_decryption_key_from_file()
    # TODO: Private key is saved in a file; read it and use it
    # TODO: Return private key to decyprt_valuables

def generate_key_pair()
    # TODO: RSA and stuff


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
