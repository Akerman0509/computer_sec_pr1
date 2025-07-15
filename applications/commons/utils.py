
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
from Crypto.Cipher import PKCS1_OAEP
from rest_framework.response import Response
from django.utils import timezone
from applications.my_app.models import User, Key

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets




# SHA - 256
def hash_passphrase(passphrase: str, salt: bytes | str = b''):
    # 1. If salt is a string (e.g., from DB), decode it
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
    def __init__(self, key: bytes, mode: str = 'CBC'):
        self.key = key
        self.mode = mode
        if mode == 'GCM':
            self.aesgcm = AESGCM(key)
        
    def encrypt(self, data: bytes) -> str:
        if self.mode == 'GCM':
            nonce = os.urandom(12)  # Nonce 12 byte cho AES-GCM
            ciphertext = self.aesgcm.encrypt(nonce, data, None)
            return json.dumps({
                'nonce': b64encode(nonce).decode('utf-8'),
                'ciphertext': b64encode(ciphertext).decode('utf-8')
            })
        else:
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv':iv, 'ciphertext':ct})
            return result
    
    def decrypt(self, encrypted_data):
        try:
            b64 = json.loads(encrypted_data)
            if self.mode == 'GCM':
                nonce = b64decode(b64['nonce'])
                ct = b64decode(b64['ciphertext'])
                return self.aesgcm.decrypt(nonce, ct, None)
            else:
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(self.key, AES.MODE_CBC, iv) 
                decrypted = cipher.decrypt(ct)
                pt = unpad(decrypted, AES.block_size)
                return pt
            
        except (ValueError, KeyError) as e:
            print(f"[decrypt] Decryption error: {e}")
            return None



# Các hằng số
SALT_SIZE = 16
ITERATIONS = 100000 # Số lần lặp cho PBKDF2, tăng tính bảo mật
RSA_BITS = 2048 # Yêu cầu: Tạo cặp khoá RSA (2048 bit).

logging.basicConfig(filename='data/logs/security.log', level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_rsa_keys():
    """Tạo một cặp khóa RSA 2048 bit."""
    key = RSA.generate(RSA_BITS)
    private_key_pem = key.export_key('PEM')
    public_key_pem = key.publickey().export_key('PEM')
    return private_key_pem, public_key_pem




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
        authLog(f"[OTP] Sent OTP to {email}" )
        return True
    except Exception as e:
        authLog(f"[OTP] Failed to send OTP to {email}: {str(e)}")
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
    authLog(f"[OTP] Generated OTP for {email}" )
    return otp

def derive_aes_key(passphrase: str, salt: bytes, key_len=32) -> bytes:
    """Derive a fixed-length AES key from passphrase using PBKDF2."""
    return PBKDF2(passphrase, salt, dkLen=key_len, count=100_000)

def encrypt_private_with_passphrase(private_key_pem: bytes, passphrase: str, salt: bytes
) -> str:
    """Encrypt the private key with the given passphrase and salt."""
    
    keyLog (f"[encrypt_private_with_passphrase] Received salt in encrypt_private_with_passphrase : {salt}")
    try :
        key = derive_aes_key(passphrase, salt)
        aes_agent = AESCipher(key)
        res = aes_agent.encrypt(private_key_pem)
        return res
    except Exception as e:
        keyLog(f"[encrypt_private_with_passphrase] Error encrypting private key: {e}")
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
    
    
def encrypt_file_with_metadata(
    file_path: str,
    sender_email: str,
    recipient_email: str,
    output_path: str = None,
    mode: bool = True
) :
    print ("-------------------------------------------------")
    
    aes_key = os.urandom(32) # Ksession
    aes_agent = AESCipher(aes_key)
    with open (file_path, 'rb') as file_in:
        data = file_in.read()
    encrypted_file_data = aes_agent.encrypt(data)
    
    # load public key
    
        # recipient_rsa_pub = RSA.import_key(f.read())
    recipient = User.objects.filter(email=recipient_email).first()
    print (f"[encrypt_file_with_metadata] Recipient: {recipient}")
    
    if not recipient:
        raise ValueError(f"Recipient with email {recipient_email} does not exist.")
    recipient_key = recipient.keys.first()
    if not recipient_key:
        raise ValueError(f"Recipient {recipient_email} does not have a public key.")
    recipient_pubkey_db = recipient_key.public_key
    pubkey_dict = json.loads(recipient_pubkey_db)
    pubkey = pubkey_dict.get('public_key', None)
    
    print (f"[encrypt_file_with_metadata] Recipient public key: {pubkey}")

    # decrypt public key b64
    pubkey = b64decode(pubkey.encode('utf-8'))
    
    recipient_pubkey = RSA.import_key(pubkey)
    rsa_cipher = PKCS1_OAEP.new(recipient_pubkey)
    encrypted_k_session = rsa_cipher.encrypt(aes_key)
    encrypted_k_session_b64 = b64encode(encrypted_k_session).decode('utf-8')
    
    metadata = {
        "sender": sender_email,
        "recipient": recipient_email,
        "filename": os.path.basename(file_path),
        "timestamp": datetime.now().isoformat(),
        "mode": mode,
        "public_key_id": recipient_key.id 
        }
    if mode == "combined":
        file_content = {
            "metadata" : metadata,
            "encrypted_k_session" : encrypted_k_session_b64,
            "file_content": json.loads(encrypted_file_data) , # contains iv + ciphertext
        }
        if not output_path:
            output_path = file_path + ".enc"
        with open(output_path, 'w') as f:
            json.dump(file_content, f, indent=2)
            
            
        return Response({
            "message": "File encrypted successfully.",
            "sender": sender_email,
            "recipient": recipient_email,
            "enc_path": output_path,
        }, status=200
        )
    else:
        key_content = {
            "metadata": metadata,
            "encrypted_k_session": encrypted_k_session_b64
        }
        enc_content= {
            "metadata": metadata,
            "file_content": json.loads(encrypted_file_data)  # contains iv + ciphertext
        }
        
        if not output_path:
            enc_path = file_path + ".enc"
            key_path = file_path + ".key"
            
        with open(key_path, 'w') as f:
            json.dump(key_content, f, indent=2)
        with open(enc_path, 'w') as f:
            json.dump(enc_content, f, indent=2)
            
        return Response({
            "message": "File encrypted successfully.",
            "sender": sender_email,
            "recipient": recipient_email,
            "enc_path": enc_path,
            "key_path": key_path
        }, status=200
        )



def detect_mode(enc_path):
    with open(enc_path, 'r') as f:
        content = json.load(f)
    
    metadata = content.get("metadata", {})
    mode = metadata.get("mode", "combined")
    return mode
        
def decrypt_file(input_passphrase: str, f_input_enc, f_output= None ):
    
    # read encrypted file
    with open(f_input_enc, 'r') as f:
        content = json.load(f)
        
    mode = detect_mode(f_input_enc)
    user_email = content.get("metadata").get("recipient", None)

    print (f"[decrypt_file] Mode: {mode}")
    print (f"[decrypt_file] User email: {user_email}")

    # load the key
    if mode == "combined":
        encrypted_k_session_b64 = content.get("encrypted_k_session", None)
        encrypted_file_content = content.get("file_content", None)
    else:
        key_path = f_input_enc.replace(".enc", ".key")
        with open(key_path, 'r') as f:
            key_content = json.load(f)
        encrypted_k_session_b64 = key_content.get("encrypted_k_session", None)
        encrypted_file_content = content.get("file_content", None)
        
        

    print (f"[decrypt_file] Encrypted session key: {encrypted_k_session_b64}")
    # print (f"[decrypt_file] Encrypted file content: {encrypted_file_content}")        
    # decrypt the session key
    key_id = content.get("metadata").get("public_key_id", None)
    user = User.objects.filter(email=user_email).first()
    if not user:
        raise ValueError(f"User with email {user_email} not found.")

    key_obj = user.keys.filter(id=key_id).first()
    if not key_obj:
        raise ValueError(f"No key found with id={key_id} for user {user_email}.")
    
    salt = user.passphrase_salt.encode('utf-8')
    
    # print (f"salt :{user.passphrase_salt}")
    # print (f"input passphrase: {input_passphrase}")    
    private_key = key_obj.private_key_enc
    
    # print (f"[decrypt_file] Private key (encrypted): {private_key}")
    
    private_key_raw = decrypt_private_with_passphrase(private_key, input_passphrase,salt)
    
    # print (f"private_key_raw: {private_key_raw}")
    
    if private_key_raw is None:
        raise ValueError("Decryption of private key failed. Check passphrase and salt.")
    
    private_key_rsa = RSA.import_key(private_key_raw)
    
    encrypted_k_session = b64decode(encrypted_k_session_b64)
    rsa_cipher = PKCS1_OAEP.new(private_key_rsa)
    k_session = rsa_cipher.decrypt(encrypted_k_session)
    
    # Decrypt file content
    file_aes = AESCipher(k_session)
    plaintext_bytes = file_aes.decrypt(json.dumps(encrypted_file_content))
    if plaintext_bytes is None:
        raise ValueError("Failed to decrypt file content.")
    # Save to output
    if f_output is None:
        # cut .enc
        f_output = f_input_enc.removesuffix('.enc')
    with open(f_output, 'wb') as f_out:
        f_out.write(plaintext_bytes)

    print(f"[+] File decrypted and saved to {f_output}")
    return Response({
        "message": "File decrypted successfully.",
        "output_file": f_output,
        "user_email": user_email
    }, status=200)

#------- Signature functions -------#
def calculate_file_hash(file_content):
    sha256_hash = hashlib.sha256()
    if isinstance(file_content, str):
        file_content = file_content.encode('utf-8')
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

def sign_file_hash(file_hash, private_key):
    try:
        file_hash_bytes = bytes.fromhex(file_hash)
        signature = private_key.sign(
            file_hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error signing file: {str(e)}")

def fix_base64_padding(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)

def verify_signature_with_public_key(file_hash, signature_b64, public_key_raw):
    try:
        if isinstance(public_key_raw, str) and public_key_raw.strip().startswith("{"):
            public_key_json = json.loads(public_key_raw)
            public_key_base64 = public_key_json["public_key"]
            public_key_pem = base64.b64decode(public_key_base64).decode("utf-8")
        else:
            public_key_pem = public_key_raw

        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        signature_bytes = base64.b64decode(fix_base64_padding(signature_b64))
        file_hash_bytes = bytes.fromhex(file_hash)

        public_key.verify(
            signature_bytes,
            file_hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        raise ValueError(f"Error while verifying signature: {str(e)}")



def create_signature_file(file_name, signature_data, output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        base_name = os.path.splitext(file_name)[0]
        sig_file_name = f"{base_name}.sig"
        sig_file_path = os.path.join(output_dir, sig_file_name)
        
        with open(sig_file_path, 'w', encoding='utf-8') as f:
            json.dump(signature_data, f, indent=2, ensure_ascii=False)
        
        return sig_file_path
    except Exception as e:
        raise ValueError(f"Error creating signature file: {str(e)}")

# def read_signature_file(sig_file_path):
#     try:
#         with open(sig_file_path, 'r', encoding='utf-8') as f:
#             return json.load(f)
#     except Exception as e:
#         raise ValueError(f"Lỗi khi đọc file chữ ký: {str(e)}")



def check_account_active(user):
    """
    Kiểm tra trạng thái tài khoản người dùng.
    Trả về True nếu tài khoản hoạt động, False nếu không.
    """
    print (user.account_status)
    if user.account_status == User.AccountStatus.BLOCKED:
        return True
    else:
        return False
    

def encrypt_large_file(file_path: str, email: str, session_key: bytes) -> dict:
    try:
        file_size = os.path.getsize(file_path)
        block_size = 1024 * 1024  # 1MB per block
        output_file = file_path + '.enc'
        metadata = {'block_count': 0, 'nonces': [], 'email': email, 'blocks': []}

        if file_size <= 5 * block_size:
            logger.info(f"File {file_path} less than 5MB, no need to split blocks - {email}")
            return {"success": False, "message": "File size less than 5MB"}

        blocks = []
        nonces = []
        aesgcm = AESCipher(session_key, mode='GCM')

        with open(file_path, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                encrypted_block = aesgcm.encrypt(block)
                block_data = json.loads(encrypted_block)
                blocks.append(block_data['ciphertext'])
                nonces.append(block_data['nonce'])

        metadata['block_count'] = len(blocks)
        metadata['nonces'] = nonces

        with open(output_file, 'w') as f:
            json.dump({'metadata': metadata, 'blocks': blocks}, f, indent=2)

        logger.info(f"File {file_path} divided into {metadata['block_count']} block and encrypt successfully - {email}")
        return {"success": True, "output_file": output_file}

    except Exception as e:
        logger.error(f"Error while encrypting file {file_path}: {str(e)} - {email}")
        return {"success": False, "error": str(e)}

# 13  
def check_key_status(email: str) -> dict:

    try:
        user = User.objects.filter(email=email).first()
        if not user:
            logger.warning(f"[check_key_status] User not found: {email}")
            return {"status": "NOT_FOUND", "error": "User does not exist"}

        key = user.keys.first() 
        if not key:
            logger.warning(f"[check_key_status] No key found for user: {email}")
            return {"status": "NOT_FOUND", "error": "No RSA key found"}

        now = timezone.now()
        # Check key expiration
        if hasattr(key, 'expires_at') and key.expires_at:
            if key.expires_at <= now:
                status = "Expired"
                details = f"Key expired at {key.expires_at}"
            elif key.expires_at <= now + timedelta(days=7):
                status = "Near expiration date"
                details = f"Key expires soon at {key.expires_at}"
            else:
                status = "Valid"
                details = f"Key is valid until {key.expires_at}"
        else:
            status = "Valid"
            details = "Key has no expiration"

        logger.info(f"[check_key_status] Key status for {email}: {status}")
        return {
            "status": status,
            "created_at": key.created_at if hasattr(key, 'created_at') else None,
            "expires_at": key.expires_at if hasattr(key, 'expires_at') else None,
            "details": details
        }

    except Exception as e:
        logger.error(f"[check_key_status] Error checking key status for {email}: {str(e)}")
        return {"status": "Error", "error": str(e)}

def renew_key(email: str, passphrase: str) -> bool:

    try:
        user = User.objects.filter(email=email).first()
        if not user:
            logger.warning(f"User not found {email}")
            return False

        passphrase_data = hash_passphrase(passphrase, user.passphrase_salt)
        if passphrase_data['hash'] != user.passphrase_hash:
            logger.warning(f"Incorrect passphrase for {email}")
            return False

        private_key_pem, public_key_pem = generate_rsa_keys()
        private_key_enc = encrypt_private_with_passphrase(
            private_key_pem, passphrase, user.passphrase_salt.encode('utf-8')
        )
        public_key_b64 = b64encode(public_key_pem).decode('utf-8')
        public_key_data = json.dumps({
            "public_key": public_key_b64,
            "created_at": timezone.now().isoformat(),
            "email": email
        })

        Key.objects.update_or_create(
            user=user,
            defaults={
                'public_key': public_key_data,
                'private_key_enc': private_key_enc,
                'created_at': timezone.now(),
                'expires_at': timezone.now() + timedelta(days=90)
            }
        )

        logger.info(f"RSA key successfully renewed/generated for {email}")
        return True

    except Exception as e:
        logger.error(f"Error renewing/generating key for {email}: {str(e)}")
        return False
    
    
import pytz  # ✅ Import this

class VNFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        # Convert to Vietnam timezone
        dt = datetime.fromtimestamp(record.created, pytz.timezone("Asia/Ho_Chi_Minh"))
        if datefmt:
            return dt.strftime(datefmt)
        else:
            return dt.strftime("%Y-%m-%d %H:%M:%S")

class MyLogger:
    def __init__(self, name, filename):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            handler = logging.FileHandler(filename)
            formatter = VNFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log(self, message):
        self.logger.info(message)


# --- Helper functions for specific logs ---

def authLog(message):
    logger = MyLogger("auth", "data/logs/auth.log")
    logger.log(message)

def keyLog(message):
    logger = MyLogger("key", "data/logs/key.log")
    logger.log(message)

def profileLog(message):
    logger = MyLogger("profile", "data/logs/profile.log")
    logger.log(message)

def fileLog(message):
    logger = MyLogger("file", "data/logs/file.log")
    logger.log(message)
    
def sigLog(message):
    logger = MyLogger("signature", "data/logs/signature.log")
    logger.log(message)
    
def adminLog(message):
    logger = MyLogger("admin", "data/logs/admin.log")
    logger.log(message)
    
def actionLog(message):
    logger = MyLogger("action", "data/logs/action.log")
    logger.log(message)