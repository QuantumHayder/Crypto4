import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import hashlib

###################################################################################################
from Cryptodome.Cipher import AES  # from pycryptodomex v-3.10.4
from Cryptodome.Random import get_random_bytes

HASH_NAME = "SHA512" # if error is raised, try lower case
IV_LENGTH = 12
ITERATION_COUNT = 65535
KEY_LENGTH = 32
SALT_LENGTH = 16
TAG_LENGTH = 16
##################################################################################################
#symmetric encryption

class AES_Encryption:
    def __init__(self, password: str):
        self.password = password
    def encrypt(self, plain_message:str):
        salt = get_random_bytes(SALT_LENGTH) 
        iv = get_random_bytes(IV_LENGTH)

        secret = self.get_secret_key(self.password, salt)
        
        cipher = AES.new(secret, AES.MODE_GCM, iv)

        encrypted_message_byte, tag = cipher.encrypt_and_digest(
            plain_message.encode("utf-8")
        )
        cipher_byte = salt + iv + encrypted_message_byte + tag

        encoded_cipher_byte = base64.b64encode(cipher_byte)
        return bytes.decode(encoded_cipher_byte)

    def decrypt(self, cipher_message):
        decoded_cipher_byte = base64.b64decode(cipher_message)

        salt = decoded_cipher_byte[:SALT_LENGTH]
        iv = decoded_cipher_byte[SALT_LENGTH : (SALT_LENGTH + IV_LENGTH)]
        encrypted_message_byte = decoded_cipher_byte[
            (IV_LENGTH + SALT_LENGTH) : -TAG_LENGTH
        ]
        tag = decoded_cipher_byte[-TAG_LENGTH:]
        secret = self.get_secret_key(self.password, salt)
        cipher = AES.new(secret, AES.MODE_GCM, iv)

        decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
        return decrypted_message_byte.decode("utf-8")

    def get_secret_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            HASH_NAME, password.encode(), salt, ITERATION_COUNT, KEY_LENGTH
        )
#############################################################################################

def aes_ed(message):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    
    ciphertext = nonce + aes.encrypt(nonce, message.encode(), None)
    plaintext = aes.decrypt(ciphertext[:12], ciphertext[12:], None)
    return key.hex(), ciphertext.hex(), plaintext.decode()


#asymmetric encryption
def rsa_ed(message):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
    return ciphertext.hex(), plaintext.decode()
    
if __name__ == "__main__":
    print(aes_ed("Hello, AES!"))
    print(rsa_ed('Hello, RSA!'))