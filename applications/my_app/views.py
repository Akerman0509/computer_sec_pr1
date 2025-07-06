from statistics import quantiles

from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
import logging
from base64 import b64encode,b64decode
from django.http import HttpResponse
logger = logging.getLogger(__name__)

from .models import User, Key, OTP
from .serializers import UserRegistrationSerializer, UserLoginSerializer, OTPVerifySerializer
from applications.commons.utils import hash_passphrase, generate_rsa_keys, AESCipher
# import redis
import json
from django.conf import settings
from datetime import datetime, timezone
from django.utils.timezone import now
import os
from applications.commons.utils import send_otp, generate_otp
from datetime import timedelta
from django.middleware.csrf import get_token
# Initialize Redis connection
# r = redis.Redis(host='localhost', port=6379, db=1)


@api_view(['POST'])
def api_login(request):
    """
    This is a simple view that handles user login.
    """
    logger.info("[Login] Received data: %s", request.data)

    email = request.data.get('email')
    input_passphrase = request.data.get('passphrase')

    serializer = UserLoginSerializer(data=request.data)
    if not serializer.is_valid():
        logger.error("[login] Invalid data: %s", serializer.errors)
        return Response(serializer.errors, status=400)
    
    

    # check if email exists in the database
    user = User.objects.filter(email=email).first()
    if not user:
        logger.warning("[login] User with email %s does not exist", email)
        return Response({"message": "User does not exist"}, status=404)
    # check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    print (f"[login] new_passphrase_data: {new_passphrase_data}")
    print (f"[login] user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        logger.warning("[login] Invalid passphrase for user: %s", email)
        return Response({"message": "Invalid credentials"}, status=401)
    
    # Send OTP to user's email
    otp = generate_otp(email)
    if not send_otp(email, otp):
        return Response({"message": "Failed to send OTP"}, status=500)

    # Lưu email vào session
    request.session['login_email'] = email
    request.session.set_expiry(300)  # Session expires after 5 minutes

    return Response({"message": "OTP sent to your email", "email": email}, status=200)
    
    
@api_view(['POST'])
def api_register(request):
    """
    This is a simple view that handles user registration.
    """
    logger.info("[Register] Received data: %s", request.data)

    serializer = UserRegistrationSerializer(data=request.data)
    if not serializer.is_valid():
        logger.error("[Register] Invalid data: %s", serializer.errors)
        return Response(serializer.errors, status=400)

    user = serializer.save()

    logger.info("[Register] User registered successfully: %s", user.email)
    
    return Response({
            "message": "User registered successfully",
            "user_id": user.id,
            "name": user.name,
    }, status=201)
    
    
    

from Crypto.Protocol.KDF import PBKDF2
def derive_aes_key(passphrase: str, salt: bytes, key_len=32) -> bytes:
    """Derive a fixed-length AES key from passphrase using PBKDF2."""
    return PBKDF2(passphrase, salt, dkLen=key_len, count=100_000)
@api_view(['POST'])
def api_create_RSA_pair(request):
    
    private_key_pem, public_key_pem = generate_rsa_keys()
    
    input_passphrase = request.data.get('passphrase')
    user_id = request.data.get('user_id')
    
        # check if email exists in the database
        
    user = User.objects.filter(pk=user_id).first()
    if not user:
        logger.warning("[api_create_RSA_pair] User with id %s does not exist", user_id)
        return Response({"message": "User does not exist"}, status=404)
    
    # check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    print (f"[api_create_RSA_pair] new_passphrase_data: {new_passphrase_data}")
    print (f"[api_create_RSA_pair] user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        logger.warning("[api_create_RSA_pair] Invalid passphrase for user_id: %s", user_id)
        return Response({"message": "Invalid credentials"}, status=401)
    
    # AES cipher private key
    passphrase_32bytes = derive_aes_key(input_passphrase, user.passphrase_salt.encode('utf-8'))
    
    aes_agent = AESCipher(passphrase_32bytes)
    
    
    private_key_enc = aes_agent.encrypt(private_key_pem)
    public_key_pem_b64 = b64encode(public_key_pem).decode('utf-8')
    # Create Key object
    key = Key.objects.create(
        user=user,
        public_key=public_key_pem_b64,
        private_key_enc=private_key_enc
    )
    key.save()
    
    return Response({
        
        "message": "RSA key pair created successfully",
        "key_id": key.id,
        "user_id": user.id,
        "public_key": public_key_pem_b64,
        "expires_at": key.expires_at.isoformat()
    }, status=201)
    

@api_view(['POST'])
def api_otp_verify(request):
    serializer = OTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        logger.error("[OTP] Invalid data: %s", serializer.errors)
        return Response(serializer.errors, status=400)

    email = serializer.validated_data['email']
    otp = serializer.validated_data['otp']

    # Check session (comment when testing)
    if email != request.session.get('login_email'):
        logger.warning("[OTP] Invalid session for %s", email)
        return Response({"message": "Invalid session"}, status=401)

    # Check OTP in database
    latest_otp = OTP.objects.filter(email=email).order_by('-otp_created').first()
    if not latest_otp:
        logger.warning("[OTP] No OTP found for %s", email)
        return Response({"message": "No OTP found"}, status=404)

    if now() > latest_otp.otp_expires:
        logger.warning("[OTP] Expired OTP for %s", email)
        return Response({"message": "OTP expired"}, status=401)


    # Delete OTP and session
    del request.session['login_email']
    latest_otp.delete()

    user = User.objects.get(email=email)
    logger.info("[OTP] Successful login for %s", email)
    return Response({
        "message": "Login successful",
        "user_id": user.id,
        "name": user.name
    }, status=200)

