from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext, is_text=True):
        """
        Encrypts plaintext using AES in CTR mode.
        Automatically handles conversion of plaintext string to bytes.
        :param plaintext: The plaintext to encrypt. Can be a string or bytes.
        :param is_text: Specifies if the plaintext is a string that needs to be encoded to bytes.
        :return: The encrypted data, with the nonce prepended.
        """
        # If the plaintext is a string and is_text is True, encode it to bytes
        if is_text and isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        nonce = os.urandom(16)  # Generate a nonce for CTR mode
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        
        return nonce + ct  # Prepend nonce to ciphertext for decryption

    def decrypt(self, ciphertext, is_text=True):
        """
        Decrypts ciphertext using AES in CTR mode.
        Automatically decodes the decrypted bytes to a string if original plaintext was a string.
        :param ciphertext: The encrypted data with the nonce prepended.
        :param is_text: Specifies if the decrypted data should be decoded to a string.
        :return: The decrypted plaintext, as bytes or a string based on is_text.
        """
        nonce, ct = ciphertext[:16], ciphertext[16:]  # Extract nonce and actual ciphertext
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        
        # If is_text is True, decode the decrypted bytes to a string
        if is_text:
            plaintext = plaintext.decode('utf-8')
        
        return plaintext
