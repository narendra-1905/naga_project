import base64
import hashlib
from AESCipher import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
class Encrypter:
    def __init__(self, text, key):
        valid_keys = ['190503', '171002', '231201', '230208']  # Array containing valid keys
        if key not in valid_keys:
            raise ValueError("The key must be a 6-digit number from the valid key array.")
        self.text = text
        self.key = key
    def generate_rsa_keypair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    def encrypt_image(self):
        aes = AESCipher(self.key)
        cipher = aes.encrypt(self.text)
        return cipher  # Convert cipher to bytes
    
    def encrypt_key(self, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        six_digit_key = self.key.zfill(6)  # Pad the key with leading zeros if necessary
        encrypted_key = cipher_rsa.encrypt(six_digit_key.encode('utf-8'))
        return base64.b64encode(encrypted_key)


