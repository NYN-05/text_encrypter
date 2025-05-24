import base64, os
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def scramble(text):
    return ''.join(chr(ord(c) ^ 0x5A) for c in text)

def descramble(text):
    return ''.join(chr(ord(c) ^ 0x5A) for c in text)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(message, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    scrambled = scramble(message)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(scrambled.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')  # Explicit UTF-8 encoding

def decrypt(token, password):
    try:
        raw = base64.b64decode(token.encode('utf-8'))  # Explicit UTF-8 decoding
        salt, iv, ciphertext = raw[:16], raw[16:32], raw[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_plain) + unpadder.finalize()

        return descramble(data.decode('utf-8'))  # Explicit UTF-8 decoding
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")  # Improved error handling
