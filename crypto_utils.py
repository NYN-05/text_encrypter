from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

def pad(text):
    pad_len = 16 - len(text.encode('utf-8')) % 16  # Ensure padding works with UTF-8
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    if pad_len < 1 or pad_len > 16:  # Validate padding length
        raise ValueError("Invalid padding")
    return text[:-pad_len]

def encrypt_message(message, password):
    key = hashlib.sha256(password.encode('utf-8')).digest()  # Explicit UTF-8 encoding
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message).encode('utf-8'))  # Explicit UTF-8 encoding
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return f"{iv}:{ct}"

def decrypt_message(ciphertext, password):
    try:
        key = hashlib.sha256(password.encode('utf-8')).digest()  # Explicit UTF-8 encoding
        iv_str, ct_str = ciphertext.split(":")
        iv = base64.b64decode(iv_str)
        ct = base64.b64decode(ct_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct).decode('utf-8')  # Explicit UTF-8 decoding
        return unpad(pt)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")  # Improved error handling
