from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
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

def Decrypt(ciphertext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
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
    return signer.verify(digest, signature)

def main():
    pk = open('RSA_demo_privkey.txt').read()
    pk = pk.split(",")
    n = pk[1]
    d = pk[2]
    n = int(n)
    d = int(d)

    pkk = open('RSA_demo_pubkey.txt').read()
    pkk = pkk.split(",")
    e = pkk[2]
    e = int(e)

    # decrypt ciphertext which has encrypted
    encrypted_text = b'\x1d\x1e\xc1ibM}z-\x85\x88\x8e\xc1;/\xd0\x00\x92\xb7f\xd9\xf4i\xc9m\xd7\x90\xcb\x99\xafwf I]\x1d\x93l\xb6\xd1\xbf\x0b\xd0\xd9:\xb8To\x82\xf7\x8b4\x93\xa2\xaa\xa3\x12O\xb9zT(\xb9\x9f\x1a\xe4IF\x86\x1e\x19\\$p]]w0\xe7\xdb\rj \x19\x06\x01q\xbd\x83\xd3\xd72\x8a\xfd\x9e\x92^\x07\xbf\x12\xf7t*\x15L\x1ac\xdb\x17\x12j\xf5\xdarZ\x85`\xf2@^\x93|\xb3\xcf\xfbo\xc5\x15\xe3\xe6\x91\xa2\xc0\x1f\xe2\xb7\xe5\t\xe7W\xed\x89\xc3j_\xf4\xf3\xe9\xb2#Iw\x01\xfc]\xd4\x7f(\x00\x9b\x18\x0b\xcd\x88\xb8\xcd\x87\x13;A\xd4H\xc2\xdb\xd3\x01&\xad_\x0c\x87\xd7\x83\n\xddS\x91\xf7\xc3\x8e"g\xa5q\xb7\x8e\xd9\x9duBC\xa6\xae\x82D\xb9\xe1\xa0R)\x9fx\xf5g\xb60\xe9\x1d%\xcf\xbf\x0e\xdb\xe1\xad\xeb\x8e\xb9C\xd4\xceaP?\x98\xff\xe9\x7f\x9f\xfbL\xed\xbddx\xd1\xd9\xdaq\x86\x17\xc2\x8c\xe14\xa3'
    msg = Decrypt(encrypted_text, RSA.construct((n, e, d), consistency_check=True))
    print(msg)
    msg = b'hello Huy'
    signature = b"21\xef}Y2\xc8\x01n\xc5\xcf]\x7f\xe4\t\xd9\x92\xcc\xca6\xe5A\x94\xa5\x14zq\x7f%\x8a\xb6\xb5z\x8e\xec\xe4\xe9\xcc(\xb8tz\xfc\x8c\rB\xc0\xa2\xa9\x92\xff\xf3'R\xb4GH\xa8\xfe\xc0i;\x11\x18\xa2\xbc\x80\x14\xaf\xb9\x9a\x91\x9f\x15\xe2n[\x9f\x81\xac\xe4\x02\xa3\xb2\xc5\xd7H`\x110\xb8\x03i\x83\xed9^\xa5S\xcd[Nb8R\xd7\x92~\xf2+\xaf<\x9e\xe4k\x99\xb1\\\x81\x1c\x8d\xc5\xb5\xcc\xf0!\xfb\x16C\x1e+\xf0Z\xb4,\xeb3\xc7\xaaL7\xa3%\xaf\x04\x931yg\xc7X\x12\xdd\xc9\xb1eG\xf2!S\xc9j\xaf\x9aRn\xc1\xd0;/]\xd44\xf0%\xc5\x10W\xc8X\xb1\xfe\t\xf7\x91\xb1\x93\n\xa94!\x00\x94\x87\x8a\xf6]Lo\xf1[K\xdd`\x89\xc4t\xef?y~~R\x1b\xec\x0e\xb7G\xef\x91\x93n\xddu\xcb\x9ak\x81.I\xe9\x08\xe3\xe8}\xeb\x92\x0c@\xc9\x85\x8bT\xc9\xed0%#\xdbT.\xe8\x01\x88\x15\x0f"
    verifirer = verify(msg, signature, RSA.construct((n, e), consistency_check=True))
    if verifirer:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

if __name__ == '__main__':
    main()