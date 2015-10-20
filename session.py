import base64
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

from config import PRIME, GENERATOR

class Session(object):

    def __gen_nonce(self):
        self.my_nonce = random.getrandbits(32)
        self.my_nonce = self.my_nonce.to_bytes(64, byteorder='little')

    def __init__(self, key):
        key = key.encode('utf-8')
        #Size of the secret exponent
        self.secret_exponent = random.getrandbits(512)
        #Should be large enough, and remembered
        self.__gen_nonce()
        self.iv = Random.new().read(AES.block_size)
        self.self_remainder = pow(GENERATOR, self.secret_exponent, PRIME)
        self.self_remainder = self.self_remainder.to_bytes(256, byteorder='little')
        #Create 256 bit key from password
        hash = SHA256.new()
        hash.update(key)
        self.shared_key = hash.hexdigest()
        self.shared_key = self.shared_key[:32:]

    #Given a decrypted nonce message, you can extract the generator^b mod Prime with this method
    @classmethod
    def extract_sender_remainder(cls, decrypted_nonce_message):
        return int.from_bytes(decrypted_nonce_message[len(decrypted_nonce_message) - 256:], byteorder='little')

    @classmethod
    def extract_nonce_from_message(cls, decrypted_nonce_message):
        return decrypted_nonce_message[:len(decrypted_nonce_message) - 256]


    def calculate_session_key(self, decrypted_nonce_message):
        return pow(Session.extract_sender_remainder(decrypted_nonce_message), self.secret_exponent, PRIME)

    def set_session_key(self, decrypted_nonce_message):
        hash = SHA256.new()
        hash.update(str(self.calculate_session_key(decrypted_nonce_message)).encode('utf-8'))
        self.session_key = hash.hexdigest()
        self.session_key = self.session_key[:32:]

    #Should be first message to send in key exchange
    def send_plaintext_nonce(self):
        return self.my_nonce

    #Should be second message sent in key exchange
    def encrypt_nonce(self, nonce):
        cipher = AES.new(self.shared_key, AES.MODE_CFB, self.iv)
        while self.my_nonce == nonce:
            self.__gen_nonce()
        return base64.b64encode(self.iv + self.my_nonce + cipher.encrypt(bytes(nonce) + bytes(self.self_remainder)))

    #Should decrypt nonce messages
    def decrypt_nonce(self, message):
        enc = base64.b64decode(message)
        iv = enc[:16]
        self.iv = iv
        sender_nonce = enc[16:16+64]
        cipher = AES.new(self.shared_key, AES.MODE_CFB, iv)
        return cipher.decrypt(enc[16+64:]), sender_nonce

    def encrypt(self, message):
        message = message
        cipher = AES.new(self.session_key, AES.MODE_CFB, self.iv)
        return base64.b64encode(cipher.encrypt(message))

    def decrypt(self, message):
        enc = base64.b64decode(message)
        cipher = AES.new(self.session_key, AES.MODE_CFB, self.iv)
        return cipher.decrypt(enc).decode('UTF-8')



def test_shit():
    alice = Session("testsharedkey")
    bob = Session("testsharedkey")

    alice_nonce = alice.send_plaintext_nonce()

    alices_nonce_encrypted_by_bob = bob.encrypt_nonce(alice_nonce)

    alices_nonce_and_bobs_remainder_decrypted_by_alice, bobs_nonce = alice.decrypt_nonce(alices_nonce_encrypted_by_bob)

    #Make sure to implement this check in the actual key exchange
    assert(alice_nonce == Session.extract_nonce_from_message(alices_nonce_and_bobs_remainder_decrypted_by_alice))

    bobs_nonce_encrypted_by_alice = alice.encrypt_nonce(bobs_nonce)

    #Grabbing only first element of tuple output by decrypt_nonce, as that nonce has been sent already.
    bobs_nonce_and_alices_remainder_decrypted_by_bob = bob.decrypt_nonce(bobs_nonce_encrypted_by_alice)[0]

    #Make sure to implement this check in the actual key exchange
    assert(bobs_nonce == Session.extract_nonce_from_message(bobs_nonce_and_alices_remainder_decrypted_by_bob))

    alice.set_session_key(alices_nonce_and_bobs_remainder_decrypted_by_alice)

    bob.set_session_key(bobs_nonce_and_alices_remainder_decrypted_by_bob)

    assert(bob.session_key == alice.session_key)
    assert(bob.iv == alice.iv)
    assert("test" == bob.decrypt(alice.encrypt("test")))

test_shit()
