# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5
# from base64 import b64encode
# from base64 import b64decode
# def decode():
#     rsa_key = RSA.importKey(open('Python/auth/private.txt', "rb").read())
#     cipher = PKCS1_v1_5.new(rsa_key)
#     global encoded_password
#     # Decrypt the data
#     decrypted_password = cipher.decrypt(encoded_password, "ERROR")
#     password = b64decode(decrypted_password)
#     return jsonify({'status': 'success', 'message': decrypted_password.decode('utf-8')})
# def encode():
#     password = b"stackoverflow"
#     rsa_key=RSA.generate(2048)
#     with open('Python/auth/private.txt', "wb") as file:
#         file.write(rsa_key.export_key('PEM'))
#     cipher = PKCS1_v1_5.new(rsa_key)
#     raw_cipher_data = b64encode(password)
#     print(raw_cipher_data)
#     # Decrypt the data
#     global encoded_password
#     encoded_password = cipher.encrypt(raw_cipher_data)
#     return jsonify({'status': 'success', 'message': encoded_password.decode('utf-8')})
# encode()
# decode()


# test 2
# from Crypto.PublicKey import RSA
# from Crypto import Random
# from Crypto.Cipher import PKCS1_OAEP
#
#
# def rsa_encrypt_decrypt():
#     key = RSA.generate(2048)
#     private_key = key.export_key('PEM')
#     public_key = key.publickey().exportKey('PEM')
#     message = input('plain text for RSA encryption and decryption:')
#     message = str.encode(message)
#
#     rsa_public_key = RSA.importKey(public_key)
#     rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
#     encrypted_text = rsa_public_key.encrypt(message)
#     #encrypted_text = b64encode(encrypted_text)
#
#     print('your encrypted_text is : {}'.format(encrypted_text))
#
#     rsa_private_key = RSA.importKey(private_key)
#     rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
#     decrypted_text = rsa_private_key.decrypt(encrypted_text)
#
#     print('your decrypted_text is : {}'.format(decrypted_text))
#
# def main():
#     rsa_encrypt_decrypt()
#
# if __name__ == '__main__':
#     main()

from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Generate 1024-bit RSA key pair (private + public key)
keyPair = RSA.generate(bits=1024)
pubKey = keyPair.publickey()
print(type(keyPair))

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = b'Message for RSA signing'
hash = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hash)
print("Signature:", binascii.hexlify(signature))

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
msg = b'Message for RSA signing'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")

# Verify invalid PKCS#1 v1.5 signature (RSAVP1)
msg = b'A tampered message'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")