import os

from Crypto.Signature import PKCS1_v1_5

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

    # TODO: hash f?
    # TODO: Don't use PKCS #1 alone, because limitation of RSA: m < n
    signing_key = read_signing_key_from_file()
    signing_object = PKCS1_v1_5.new(signing_key)
    signature = signing_object.sign(f)

    return bytes(signature, "ascii") + f


def read_signing_key_from_file(self)
    # TODO: Private key is saved in a file; read & unhash it (?)
    signing_key = None
    return signing_key


if __name__ == "__main__":
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

