from statistics import quantiles

from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
import logging
from base64 import b64encode,b64decode
from django.http import HttpResponse
logger = logging.getLogger(__name__)

from .models import User, Key, OTP
from .serializers import UserRegistrationSerializer, UserLoginSerializer, OTPVerifySerializer
from applications.commons.utils import hash_passphrase, generate_rsa_keys, AESCipher,derive_aes_key, encrypt_private_with_passphrase, decrypt_private_with_passphrase

# import redis
import json
from django.conf import settings
from datetime import datetime, timezone
from django.utils import timezone  
from django.utils.timezone import now
import os
from applications.commons.utils import send_otp, generate_otp
from datetime import timedelta
from django.middleware.csrf import get_token
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
import qrcode
import io
import base64
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from PIL import Image
from pyzbar.pyzbar import decode
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
    private_key_enc = encrypt_private_with_passphrase(private_key_pem, input_passphrase, user.passphrase_salt.encode('utf-8'))
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
    # if email != request.session.get('login_email'):
    #     logger.warning("[OTP] Invalid session for %s", email)
    #     return Response({"message": "Invalid session"}, status=401)

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


@api_view(['POST'])
def api_otp_verify(request):
    serializer = OTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        logger.error("[OTP] Invalid data: %s", serializer.errors)
        return Response(serializer.errors, status=400)

    email = serializer.validated_data['email']
    otp = serializer.validated_data['otp']

    # Check session (comment when testing)
    # if email != request.session.get('login_email'):
    #     logger.warning("[OTP] Invalid session for %s", email)
    #     return Response({"message": "Invalid session"}, status=401)

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




@api_view(['POST'])
def api_update_user(request):
    """
    This is a simple view that handles user update.
    """
    logger.info("[Update User] Received data: %s", request.data)

    user_id = request.data.get('user_id')
    name = request.data.get('name')
    phone_number = request.data.get('phone_number')
    address = request.data.get('address')
    birth_day = request.data.get('birth_day')

    user = User.objects.filter(pk=user_id).first()
    if not user:
        logger.warning("[Update User] User with id %s does not exist", user_id)
        return Response({"message": "User does not exist"}, status=404)

    if name:
        user.name = name
    if phone_number:
        user.phone_number = phone_number
    if address:
        user.address = address
    if birth_day:
        try:
            user.birth_day = datetime.strptime(birth_day, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        except ValueError:
            logger.error("[Update User] Invalid date format for birth_day: %s", birth_day)
            return Response({"message": "Invalid date format for birth_day"}, status=400)
    
    user.save()
    logger.info("[Update User] User updated successfully: %s", user.email)
    res = {
            "message": "User updated successfully",
            "user_id": user.id,
            "name": user.name,
            "email": user.email,
            "phone_number": user.phone_number,
            "address": user.address,
        }
    

    # handle passphrase change if provided
    curr_passphrase = request.data.get('current_passphrase')
    new_passphrase = request.data.get('new_passphrase')
    if curr_passphrase and new_passphrase:
        response = handle_passphrase_change(user_id, curr_passphrase, new_passphrase)
        print (f"[api_update_user] response: {response}")
        
        if response!= 1:
            return response
        else:
            res['message'] += " and passphrase changed successfully"

    
    
    return Response(res, status=200)
    
    
def handle_passphrase_change(user_id, input_passphrase, new_passphrase):
    
    user = User.objects.filter(pk=user_id).first()
    if not user:
        logger.warning("[handle_passphrase_change] User with id %s does not exist", user_id)
        return Response({"message": "User does not exist"}, status=404)
    
    # check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    # print (f"[handle_passphrase_change] new_passphrase_data: {new_passphrase_data}")
    # print (f"[handle_passphrase_change] user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        logger.warning("[handle_passphrase_change] Invalid passphrase for user_id: %s", user_id)
        return Response({"message": "Invalid credentials"}, status=401)
    
    # decrypt all private keys of the user
    keys = Key.objects.filter(user=user)
    if not keys:
        logger.warning("[handle_passphrase_change] No keys found for user_id: %s", user_id)
        return Response({"message": "No keys found for user"}, status=404)
    
    # AES cipher private key
    
    new_salt = os.urandom(16)
    new_salt = b64encode(new_salt).decode('utf-8')  # Base64 encode the new salt | 5h for this shit
    print (f"[handle_passphrase_change+++++] new_salt: {new_salt}")
    for key in keys:
        try:
            decrypt = decrypt_private_with_passphrase(key.private_key_enc, input_passphrase, user.passphrase_salt.encode('utf-8'))
            if decrypt is None:
                logger.error(f"[handle_passphrase_change] Failed to decrypt private key for user_id {user_id}")
                return Response({"error": "Error decrypting private keys"}, status=400)
            
            # Re-encrypt with new passphrase
            
            key.private_key_enc  = encrypt_private_with_passphrase(decrypt, new_passphrase, new_salt)
            key.save()
        except Exception as e:
            logger.error("[handle_passphrase_change] Error decrypting private key for user_id %s: %s", user_id, str(e))
            return Response({"message": "Error decrypting private keys"}, status=500)
        
    # Update user's passphrase salt and hash
    passphrase_data = hash_passphrase(new_passphrase, new_salt)
    user.passphrase_salt = passphrase_data['salt']
    user.passphrase_hash = passphrase_data['hash']
    # print (f"[handle_passphrase_change] user.passphrase_salt: {user.passphrase_salt}")
    # print (f"[handle_passphrase_change] user.passphrase_hash: {user.passphrase_hash}")
    
    
    
    user.save()

    return 1


@api_view(['POST'])
#@login_required
def generate_qr_code(request):
    user_id = request.data.get("user_id")
    input_passphrase = request.data.get("passphrase")

    if not user_id or not input_passphrase:
        return Response({"message": "Missing user_id or passphrase"}, status=400)

    user = User.objects.filter(id=user_id).first()
    if not user:
        return Response({"message": "User not found"}, status=404)

    passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    if passphrase_data['hash'] != user.passphrase_hash:
        return Response({"message": "Invalid passphrase"}, status=401)

    key = Key.objects.filter(user=user, expires_at__gt=timezone.now()).order_by('-created_at').first()

    if not key:
        private_key_pem, public_key_pem = generate_rsa_keys()
        public_key_b64 = base64.b64encode(public_key_pem).decode('utf-8')
        private_key_enc = encrypt_private_with_passphrase(private_key_pem, input_passphrase, user.passphrase_salt.encode('utf-8'))

        key = Key.objects.create(
            user=user,
            public_key=public_key_b64,
            private_key_enc=private_key_enc,
            expires_at=timezone.now() + timedelta(days=90)
        )

    qr_data = json.dumps({
        "email": user.email,
        "creation_date": key.created_at.strftime("%Y-%m-%d"),
        "public_key": key.public_key
    })

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_file = ContentFile(img_byte_arr.getvalue(), name=f"qr_{user.email}.png")

    key.qr_code = img_file
    key.save()

    return Response({
        "message": "QR code generated successfully",
        "qr_code_url": key.qr_code.url
    }, status=200)

@api_view(['POST'])
# @login_required
def read_qr_code(request):
    if request.method == 'POST' and request.FILES.get('qr_image'):
        qr_image = request.FILES['qr_image']
        fs = FileSystemStorage(location='applications/data/uploaded_qr/')
        filename = fs.save(qr_image.name, qr_image)
        file_path = fs.path(filename)

        image = Image.open(file_path)
        decoded_objects = decode(image)
        qr_data = {}
        message = "Failed to read QR code."

        if decoded_objects:
            qr_content = decoded_objects[0].data.decode('utf-8')
            try:
                qr_data = json.loads(qr_content)
                message = f"QR code read successfully for {qr_data['email']}."
                logger.info(f"QR code read successfully for {qr_data['email']}")
            except json.JSONDecodeError:
                message = "Invalid QR code format."
                logger.error("Invalid QR code format")

        return Response({
            "message": message,
            "qr_data": qr_data
        })

    return Response({
        "message": "No file uploaded or incorrect key name. Use 'qr_image'."
    }, status=400)