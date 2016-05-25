import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

# Public RSA key for encryption of data
encryption_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2mzZeA2+fsjCGoTjRFuU\nivZifvfMPHOmMaT6p8lRjxLlRegd6TzYclEtADqxw5Nch4SueWeHKIq+YmZINnUA\nyLGQGZDKaara+ifySkdcjhQq0KXpOcDhTMSHwnDiuGR29snLhvex3fGYjARBZAxk\nvaSvR1EZqveDkTI68n9d5h+5HHTJq8+nIntOgIvLkjCUo5zcOTY9N2PmgV7hBsQ7\nAV0AXlIRRXFgw/3FKeF1ewKydBpCOAPD6iieY5qPw7FXyh1w7/8bKnbO/sndsq8W\nTni28TnlpIZ/Fr3jgGFQqMJhY97L/KxNumcZd5GoVy4pfmk79cn3w/aozEX8NbQ5\nVUkETUQsjAK8POBwJpRRjgseHRYui0hFTIr4gOfBJ8yyJPzEPz4mn2M2YjSDhqOL\nQrNnsLn7TUmZTEyRxcaJKDdQgTtcTzrwP6PsOKIyxO7KKfrX6fXJPOT19apK2kNS\nUDCCOH3xao9QqWUeHTnhhZiGErrQL6TVN+QIQ2jLIK+Bxe6z4Jd7dykiM0lrev0W\nW60tjvd0IKwQSwvkQoYZi7qAgZ+3Mksl17Y24huw8NVvmOFJLxCINVJop1fG7PKr\nuHCS2s04DIq5jw8icWGJYsED6Wzr8ddgmofYcYAbe7YVKrPRAZ96NducfdoSQKjI\nHXiSymmlKNflAOyD6cjnb+cCAwEAAQ==\n-----END PUBLIC KEY-----'
###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    key = RSA.importKey(encryption_key)
    rsa_cipher = PKCS1_v1_5.new(key)
    encrypted_data = rsa_cipher.encrypt(data)
    return encrypted_data

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
    # Naive verification by ensuring the first line has the "passkey"
    lines = f.split(bytes("\n", "ascii"), 1)
    first_line = lines[0]
    if first_line == bytes("Caesar", "ascii"):
        return True
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
