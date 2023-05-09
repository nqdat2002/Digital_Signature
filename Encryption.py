from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

from base64 import b64encode, b64decode
import hashlib
hash = "SHA-256"

def newkeys(keysize):
   random_generator = Random.new().read
   key = RSA.generate(keysize, random_generator)
   private, public = key, key.publickey()
   return public, private

def importKey(externKey):
   return RSA.importKey(externKey)

def getpublickey(priv_key):
   return priv_key.publickey()

def Encrypt(message, pub_key):
   cipher = PKCS1_OAEP.new(pub_key)
   return cipher.encrypt(message)

def sign(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    signer = PKCS1_v1_5.new(priv_key)

    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)

def main():
    print("Enter the message to encrypt")
    msg = input()
    pk = open('RSA_demo_pubkey.txt').read()
    pk = pk.split(",")
    n = pk[1]
    e = pk[2]

    pkk = open('RSA_demo_privkey.txt').read()
    pkk = pkk.split(",")
    d = pkk[2]
    d = int(d)

    n = int(n)
    e = int(e)
    print(n)
    print(e)
    print(d)

    # print(msg.encode())
    # digest = hashlib.sha256(msg.encode('ascii')).hexdigest()

    # encrypted text
    encrypted_text = Encrypt(bytes(msg.encode()), RSA.construct((n, e), consistency_check=True))
    print(type(encrypted_text))

    # signature
    signner = sign(msg.encode(), RSA.construct((n, e, d), consistency_check=True))
    print(signner)


if __name__ == '__main__':
    main()