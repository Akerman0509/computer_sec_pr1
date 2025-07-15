from django.db import models
from django.utils import timezone
import datetime
from datetime import timedelta
import secrets
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

# User

 
# email
# name
# birth_day
# phone_number
# address
# passphrase
# role
# passphrase_salt 	TEXT (Base64)
# passphrase_hash	TEXT (SHA-256)

# otp_code
# otp_expires_at
# created_at

class User(models.Model):
    class Role(models.TextChoices):
        USER = 'USER', 'User'
        ADMIN = 'ADMIN', 'Admin'
    class AccountStatus(models.TextChoices):
        ACTIVE = 'ACTIVE', 'Active'
        BLOCKED = 'BLOCKED', 'Blocked'
    email =  models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=50)
    birth_day = models.DateField() # YYYY-MM-DD
    phone_number = models.CharField(max_length=20)
    address = models.CharField(max_length=255)
    passphrase_salt = models.TextField()  # Base64 encoded
    passphrase_hash = models.TextField()  # SHA-256 hash
    
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.USER
    )
    account_status = models.CharField(
        max_length=10,
        choices=AccountStatus.choices,
        default=AccountStatus.ACTIVE
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def is_authenticated(self):
        return True

def get_default_expiration():
    """Returns the current time + 90 days."""
    return timezone.now() + datetime.timedelta(days=90)
class Key(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='keys')
    public_key = models.TextField()  # Base64 encoded
    private_key_enc = models.TextField() # JSON-encoded {iv, ciphertext}, both base64
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(default=get_default_expiration)
    qr_code = models.ImageField(upload_to='qr_codes/', blank=True, null=True)
    
    def get_default_expiration(self):
        return timezone.now() + datetime.timedelta(days=90)
    
    def __str__(self):
        return f"Key for {self.user.email} (expires at {self.expires_at})"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def get_expiration_days(self):
        if self.is_expired():
            return 0
        return (self.expires_at - timezone.now()).days
    

#OTP
class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    otp_created = models.DateTimeField()
    otp_expires = models.DateTimeField()


class DigitalSignature(models.Model):
    signer = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64)  
    signature = models.TextField()  
    created_at = models.DateTimeField(auto_now_add=True)
    signature_file_path = models.CharField(max_length=500, blank=True)
    
    def __str__(self):
        return f"{self.file_name} - {self.signer.email} - {self.created_at}"


#Token for test 
class CustomToken(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=get_default_expiration)

    def is_expired(self):
        return timezone.now() > self.expires_at

    @staticmethod
    def generate_token(user):
        key = secrets.token_hex(20)
        return CustomToken.objects.create(
            user=user,
            key=key,
            expires_at=timezone.now() + timedelta(days=1) 
        )
    
# Authentication for Signature

class CustomTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Token '):
            return None

        token_key = auth_header.split(' ')[1]

        try:
            token = CustomToken.objects.get(key=token_key)
        except CustomToken.DoesNotExist:
            raise AuthenticationFailed("Invalid token")

        return (token.user, None)