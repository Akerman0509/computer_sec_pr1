
import re
import os
import hashlib
import json
import smtplib
import logging
import random
from datetime import timedelta
from applications.my_app.models import OTP
from rest_framework import serializers
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA
from email.mime.text import MIMEText
from datetime import datetime
from django.conf import settings
from django.core.mail import send_mail
from Crypto.Protocol.KDF import PBKDF2


# SHA - 256
def hash_passphrase(passphrase: str, salt: bytes | str = b''):
    # 1. If salt is a string (e.g., from DB), decode it
    print (f"[hash_passphrase] Received salt=======================================================: {salt}")
    salt = b64decode(salt) if isinstance(salt, str) else salt
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
            print (f"iv: {iv}")
            print (f"ct: {ct}")
            decrypted = cipher.decrypt(ct)
            print (f"[decrypt] Decrypted bytes: {decrypted}")
            print ("++++++++++++++++++++++++++++++++++++++++++++++++++")
            pt = unpad(decrypted, AES.block_size)
            print (f"[decrypt] Unpadded plaintext: {pt}")
            
            return pt
        except (ValueError, KeyError) as e:
            print(f"[decrypt] Decryption error: {e}")
            return None



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


logging.basicConfig(filename='data/logs/security.log', level=logging.INFO)
logger = logging.getLogger(__name__)

def send_otp(email, otp):
    """Gửi OTP qua email."""
    try:
        send_mail(
            subject='Your OTP Code',
            message=f'Your OTP is: {otp}\nExpires in 5 minutes.',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
        )
        logger.info("[OTP] Sent OTP to %s", email)
        return True
    except Exception as e:
        logger.error("[OTP] Failed to send OTP to %s: %s", email, str(e))
        return False

def generate_otp(email):
    otp = str(random.randint(100000, 999999))
    created_at = datetime.now()
    expires_at = created_at + timedelta(minutes=5)
    OTP.objects.create(
        email=email,
        otp=otp,
        otp_created=created_at,
        otp_expires=expires_at,
    )
    logger.info("[OTP] Generated OTP for %s", email)
    return otp

def derive_aes_key(passphrase: str, salt: bytes, key_len=32) -> bytes:
    """Derive a fixed-length AES key from passphrase using PBKDF2."""
    return PBKDF2(passphrase, salt, dkLen=key_len, count=100_000)

def encrypt_private_with_passphrase(private_key_pem: bytes, passphrase: str, salt: bytes
) -> str:
    """Encrypt the private key with the given passphrase and salt."""
    
    print (f"[encrypt_private_with_passphrase] Received salt in encrypt_private_with_passphrase : {salt}")
    try :
        key = derive_aes_key(passphrase, salt)
        aes_agent = AESCipher(key)
        res = aes_agent.encrypt(private_key_pem)
        return res
    except Exception as e:
        print(f"[encrypt_private_with_passphrase] Error encrypting private key: {e}")
        return None



def decrypt_private_with_passphrase(
    encrypted_private_key: str, passphrase: str, salt: bytes
) -> bytes:
    try:
        key = derive_aes_key(passphrase, salt)
        aes_agent = AESCipher(key)
        decrypted_private_key = aes_agent.decrypt(encrypted_private_key)
        
        if decrypted_private_key is None:
            raise ValueError("Decryption failed, invalid passphrase or encrypted data.")
        
        return decrypted_private_key
    except Exception as e:
        print(f"[decrypt_private_with_passphrase] Error decrypting private key: {e}")
        return None