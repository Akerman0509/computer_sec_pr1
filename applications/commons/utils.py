
import re
import os
import hashlib
import json
from rest_framework import serializers
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA


def hash_passphrase(passphrase: str, salt: bytes | str = b''):
    # 1. If salt is a string (e.g., from DB), decode it
    if isinstance(salt, str):
        try:
            salt = b64decode(salt)
        except Exception as e:
            raise ValueError("Invalid salt format. Expected base64-encoded string.") from e

    # 2. Generate salt if not provided
    if not salt:
        print("[hash_passphrase] No salt provided, generating new salt.")
        salt = os.urandom(16)
        
    combined = salt + passphrase.encode('utf-8')
    
    # 3. Hash bằng SHA-256
    hash_digest = hashlib.sha256(combined).digest()

    # 4. Mã hóa base64 để lưu an toàn
    salt_b64 = b64encode(salt).decode('utf-8')
    hash_b64 = b64encode(hash_digest).decode('utf-8')

    # 5. Trả về hoặc lưu
    return {
        "salt": salt_b64,
        "hash": hash_b64
    }
    
def validate_passphrase_email(passphrase: str, email: str):
    """
    Validate passphrase strength and email format.
    Gợi ý: ít nhất 8 ký tự, có chữ hoa, số, ký hiệu.
    """
    if len(passphrase) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', passphrase):
        raise serializers.ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', passphrase):
        raise serializers.ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', passphrase):
        raise serializers.ValidationError("Password must contain at least one number.")
    if not re.search(r'[\W_]', passphrase):  # \W matches any non-word character (equivalent to [^a-zA-Z0-9_])
        raise serializers.ValidationError("Password must contain at least one symbol.")

    # validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise serializers.ValidationError("Invalid email format.")
    
    return True



class AESCipher:
    def __init__(self, key: bytes):
        self.key = key

    
    def encrypt(self, data: bytes) -> str:
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        # print(result)
        return result
    
    def decrypt(self, encrypted_data):
        try:
            b64 = json.loads(encrypted_data)
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(self.key, AES.MODE_CBC, iv) 
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            # print("The message was: ", pt)
        except (ValueError, KeyError):
            print("Incorrect decryption")
        
        return pt



# Các hằng số
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits for AES
ITERATIONS = 100000 # Số lần lặp cho PBKDF2, tăng tính bảo mật
RSA_BITS = 2048 # Yêu cầu: Tạo cặp khoá RSA (2048 bit).


def generate_rsa_keys():
    """Tạo một cặp khóa RSA 2048 bit."""
    key = RSA.generate(RSA_BITS)
    private_key_pem = key.export_key('PEM')
    public_key_pem = key.publickey().export_key('PEM')
    return private_key_pem, public_key_pem
