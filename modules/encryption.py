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

IV_LENGTH = 12
TAG_LENGTH = 16

class AES_Encryption:
    def __init__(self, password: str):
        # Per spec: SHA-256 of master password IS the AES data key
        self.key = hashlib.sha256(password.encode()).digest()  # 32 bytes = AES-256

    def encrypt(self, plain_message: str):
        iv = get_random_bytes(IV_LENGTH)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        encrypted_message_byte, tag = cipher.encrypt_and_digest(
            plain_message.encode("utf-8")
        )
        cipher_byte = iv + encrypted_message_byte + tag
        return base64.b64encode(cipher_byte).decode()

    def decrypt(self, cipher_message: str):
        decoded = base64.b64decode(cipher_message)
        iv = decoded[:IV_LENGTH]
        encrypted_message_byte = decoded[IV_LENGTH:-TAG_LENGTH]
        tag = decoded[-TAG_LENGTH:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(encrypted_message_byte, tag)
        return decrypted.decode("utf-8")
    
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