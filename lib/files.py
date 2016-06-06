import os

import Crypto.Cipher.PKCS1_v1_5
import Crypto.Signature.PKCS1_v1_5

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

# Public RSA key for encryption of data
verification_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsbFhOR17m2fJ/TygGRNF\nSmrW3cJx2vEPSi9X3y4Srgtr5vilfYcIeVy98ujB311w5V0mdG0kyQnQrATb1evV\nTmcU6srzFV42wGTwTfveVVH/EmMV9NafErGIMsPxGlKXonLuUJqmameQ83S9XIkN\nBaV98yZpadfZ1Dr/MgDyJjOMbsMoeeNhj+gK9K5F7T7R8arTlKGmzlhuebr2ZaKp\nXTKCPgegdzhacqNOIDfmnVNugU5LIM4TjFV5UwG50/YsUqQd7BFXADf8Rt8yFbyT\n/RUqbi4/ba9s72dA/cm+iBunX7P4bkbq0YvKbPcuAf3KgW/AHTOsWR4HrH+qhBS5\nd0yF60h/iaOC6808ENQcTDuxJrbOErcHNxTfE5jgn6dhBfGeMh9MInO8N2bzrigd\n6r/KznCjNzA13J0xj5TpNGvyAF8jQxg6sSH9+r0+N205wZbGWOF7Y8wFssyXvfg6\nxYEgMtpkNj5esYSobNMnhYw6iVSeErG7qeQh2WrkwNphVmZPOT+5sr7SUeZnccCT\nd8elaqGEBls5peSMQAknFXS1PqLHCr2MQNmkCX8YrAtpE47v04yi6ijDx9jRIGLw\na+F0FjNzWhlFnab6egRvCHSVQEabkPMVprHSoFn01RoEFsdjh3G3e8wGXSbmgYSc\naFk//TriUJDEEBNVK2Qf0LcCAwEAAQ==\n-----END PUBLIC KEY-----'
encryption_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsaiQEzOBdTe1CxXH3mF2\ntEyiU5hNk6yZ8mirdmO1z+wvkFnlp+deMt7zKNAc08CJNLIEXr/Jm6mDoMaCR1sS\n7NpmL04FqzeRqbsVFMd2eiP05JuY2UZi0tbIeN65ok0NwZHaSTcxUs8ETNuctmxQ\nGmER/CizIMOUjALcTKLW77w1ONJENDmspZKco1SsIbH+CKA4tG3E/fmhEF/xWe3l\nz0JDG3TwIuqjAaJxqiVMIsqptPMXCMEndmJylAlB/eqz2U2kGXI0OdUUcpojF4DJ\ntlmMeTfQFbHo9wtdgngNWtuUkQiOBhKflfIq79ZaII89GMgmoEbGb6NJETXHUL5z\nL0Ss0jIaty3ps9moNyS1l5IUI2ump8EVYpx+CpaW4eACQU1H8D8XKD2NMik7SooD\nWwr6Tyv6IDxZIjL9jA2rmXRbR4+DJwEkKd9sUMRycHFcHypRAGFgVT3WuwstkTbV\n4iuTqIMBiLb6oqUSH7/gYnlCWgqy0gEuc6JY3NV33d3NqrPaItphhR+68l7QEGl6\nX6AO+6ADQANDczeWwePZj6fx4wkC8EygNdOMiIO0Ctj/8JLqsHtIFIvK0Tqwy2c5\nmIc9n/vha/+22YeF6WuJEJzKPsUMG2A96TDLm4PvNyFrDhHk+U4lOtqNrm3vzzZZ\nVqNWMAhJKuZbFTkk6kzI6g8CAwEAAQ==\n-----END PUBLIC KEY-----'
###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master

    rsa_key = RSA.importKey(encryption_key)
    rsa_cipher = Crypto.Cipher.PKCS1_v1_5.new(rsa_key)
    session_key = get_random_bytes(16)
    iv = get_random_bytes(AES.block_size)

    # Encrypt the session key with RSA
    encrypted_session_key = rsa_cipher.encrypt(session_key)

    # Encrypt the data with 128-bit AES, using the session key
    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv)

    encrypted_data = aes_cipher.encrypt(data)

    return encrypted_session_key + iv + encrypted_data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)
    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here

    key_obj = RSA.importKey(verification_key)

    # Split the file into the signature and the contents of the file
    lines = f.split(bytes("\n\n\n", "ascii"), 1)
    signature = lines[0]
    file_contents = lines[1]

    # Hash the message to compress it to 128 bits before verification
    # Hashing ensures that RSA will be able to verify/decrypt the message
    # (limitation of RSA is that m must be less than n)
    hashed_file = MD5.new(file_contents)
    sig_scheme = Crypto.Signature.PKCS1_v1_5.new(key_obj)

    # Check if the signature is authentic
    if sig_scheme.verify(hashed_file, signature):
        return True
    else:
        return False

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass

