# # import hashlib
# #
# # my_str = 'bobbyhadz.com'
# #
# # # ✅ encode str to bytes
# # my_hash = hashlib.sha256(my_str.encode('utf-8')).hexdigest()
# #
# # # 👇️ c5fd426de8044e3ab34fd5005c0da08383a15fd018aeb76f903fb59c6de537de
# # print(my_hash)
#
# from Crypto.Cipher import Salsa20
# key = b'0123456789012345'
# cipher = Salsa20.new(key)
# ciphertext =  cipher.encrypt(b'The secret I want to send.')
# ciphertext += cipher.encrypt(b'The second part of the secret.')
# print(cipher.nonce)
# print(ciphertext)


if __name__ == '__main__':
    main()