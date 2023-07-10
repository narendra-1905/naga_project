import base64
from AESCipher import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Decrypter:
    def __init__(self, cipher):
        self.cipher = cipher
    
    def decrypt_key(self, private_key):
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_key = base64.b64decode(self.cipher)
        decrypted_key = cipher_rsa.decrypt(encrypted_key)
        six_digit_key = decrypted_key[6]  # Extract the first six digits
        return six_digit_key.decode('utf-8')
    
    def decrypt_image(self, key):
        aes = AESCipher(key)
        base64_decoded = aes.decrypt(self.cipher)
        fh = open("decryptedImage.png", "wb")
        fh.write(base64.b64decode(base64_decoded))
        fh.close()
        return base64.b64decode(base64_decoded)


# Example usage
# decrypter = Decrypter(cipher)
# decrypted_key = decrypter.decrypt_key(private_key)
# decrypted_image = decrypter.decrypt_image(decrypted_key)
