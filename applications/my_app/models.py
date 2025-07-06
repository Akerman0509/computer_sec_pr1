from django.db import models
from django.utils import timezone
import datetime


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
    email =  models.CharField(max_length=50)
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
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    


# RSA_key

# user_id
# public_key
# private_key_enc
# created_at
# expires_at


def get_default_expiration():
    """Returns the current time + 90 days."""
    return timezone.now() + datetime.timedelta(days=90)
class Key(models.Model):
    
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.TextField()  # Base64 encoded
    private_key_enc = models.TextField() # JSON-encoded {iv, ciphertext}, both base64
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(default=get_default_expiration)
    
    
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
    