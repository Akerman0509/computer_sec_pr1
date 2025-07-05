from statistics import quantiles

from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
import logging
from django.http import HttpResponse
logger = logging.getLogger(__name__)

from .models import User, Key
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from applications.commons.utils import hash_passphrase, generate_rsa_keys, AESCipher
# import redis
import json
from django.conf import settings
from datetime import datetime, timezone
import os

# Initialize Redis connection
# r = redis.Redis(host='localhost', port=6379, db=1)


@api_view(['POST'])
def api_login(request):
    """
    This is a simple view that handles user login.
    """
    logger.info("[Login] Received data: %s", request.data)

    email = request.data.get('email')
    passphrase = request.data.get('passphrase')

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
    
    new_passphrase_data = hash_passphrase(passphrase, user.passphrase_salt)
    print (f"[login] new_passphrase_data: {new_passphrase_data}")
    print (f"[login] user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        logger.warning("[login] Invalid passphrase for user: %s", email)
        return Response({"message": "Invalid credentials"}, status=401)
    
    return Response({
            "messsage": "Login successful", 
            "user_id": user.id,
            "name": user.name,
    }, status=200)
    
    
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
    
    
    
# def api_create_RSA_pair(request):
    