import base64
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

from config import PRIME, GENERATOR


class Session(object):

    def __gen_nonce(self):
        self.my_nonce = random.getrandbits(5)
        self.my_nonce = self.my_nonce.to_bytes(64, byteorder='little')

    def __init__(self, key):
        key = key.encode('utf-8')
        #Min must be greater than 2048 bits at least
        self.secret_exponent = random.randint(3000, 900000)
        #Should be large enough, and remembered
        self.__gen_nonce()
        self.iv = Random.new().read(AES.block_size)
        self.self_remainder = (GENERATOR**self.secret_exponent) % PRIME
        self.self_remainder = self.self_remainder.to_bytes(256, byteorder='little')
        #Create 256 bit key from password
        hash = SHA256.new()
        hash.update(key)
        self.shared_key = hash.hexdigest()
        self.shared_key = self.shared_key[:32:]

    def send_plaintext_nonce(self):
        return self.my_nonce

    def encrypt_nonce(self, nonce):
        cipher = AES.new(self.shared_key, AES.MODE_CFB, self.iv)
        # return base64.b64encode(self.iv + cipher.encrypt(nonce))
        while self.my_nonce == nonce:
            __gen_nonce()
        return base64.b64encode(self.iv + self.my_nonce + cipher.encrypt(bytes(nonce) + bytes(self.self_remainder)))

    def decrypt_nonce(self, message):
        enc = base64.b64decode(message)
        iv = enc[:16]
        sender_nonce = enc[16:16+64]
        cipher = AES.new(self.shared_key, AES.MODE_CFB, iv)
        return cipher.decrypt(enc[16+64:]), sender_nonce

    def decrypt(self, ciphertext):
        pass

# class Message(Object):
#
#     def __init__(self, iv, message):
#         self.iv = iv
#         self.message = message
#
# class SessionMessage(Object):
#
#     def __init__(self, message, key, iv):
#         cipher = AES.new(key, AES.MODE_CFB, iv)
#         self.message = iv + cipher.encrypt()
#

x = Session("test")
y = Session("test")

xnonce = x.send_plaintext_nonce()
print(int.from_bytes(xnonce, byteorder='little'))

xnonce_encrypted_by_y = y.encrypt_nonce(xnonce)
print(xnonce)
# print(xnonce_encrypted_by_y)
print("SPACING")
xnonce_decrypted_by_x, ynonce = x.decrypt_nonce(xnonce_encrypted_by_y)
# xy = xnonce_decrypted_by_x.decode(encoding='UTF-8')
# print((xy[:64]))
print("SPACING 2")
print(ynonce)
print(int.from_bytes(ynonce, byteorder='little'))
print(int.from_bytes(y.send_plaintext_nonce(), byteorder='little'))
print("SPACING 3")
print(int.from_bytes(xnonce_decrypted_by_x[:64], byteorder='little'))
