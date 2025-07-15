from statistics import quantiles

from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
import logging
from base64 import b64encode,b64decode
from django.http import HttpResponse, Http404
logger = logging.getLogger(__name__)
from applications.my_app.models import User, Key, OTP, DigitalSignature, CustomToken
from .serializers import UserRegistrationSerializer, UserLoginSerializer, OTPVerifySerializer
from applications.commons.utils import hash_passphrase, generate_rsa_keys, AESCipher,derive_aes_key, encrypt_private_with_passphrase, decrypt_private_with_passphrase,encrypt_file_with_metadata, decrypt_file, calculate_file_hash, sign_file_hash, create_signature_file, verify_signature_with_public_key,check_account_active, encrypt_large_file, renew_key, check_key_status, authLog, keyLog, profileLog,fileLog, sigLog,adminLog,actionLog
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
from django.shortcuts import render, get_object_or_404, redirect
import qrcode
import io
import base64
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from PIL import Image
import shutil
from pyzbar.pyzbar import decode
from django.http import FileResponse
from django.contrib import messages
from rest_framework.authtoken.models import Token
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import quote, unquote
# Initialize Redis connection
import redis
r = redis.Redis(host='localhost', port=6379, db=1)




def rate_limiter_wrong_login(email, counter=1):
    rate_limit_seconds = 60*5 # 5 minutes for 5 wrong attempts
    max_requests = 5
    redis_key = f"rate_limit:{email}"
        
    if counter == 1:
        r.incr(redis_key)
        r.expire(name=redis_key, time=rate_limit_seconds, nx=True)
    current = r.get(redis_key)

    
    time_left = r.ttl(redis_key)
    # convert to minutes + seconds
    time_format = "{:02}:{:02}".format(time_left // 60, time_left % 60) if time_left > 0 else "00:00"
    # print (f"Current requests for {email}: {current}; Time left: {time_left} seconds")
    if current and int(current) >= max_requests:
            status = "blocked"
    else :
        status = "allowed"
    return {
        "status": status,
        "time_left": time_format,
        "current_requests": int(current) if current else 0
    }


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    """
    This is a simple view that handles user login.
    """
    rate_limiter_status = rate_limiter_wrong_login(request.data.get('email', ''), 0)
    authLog (f"[Login] Rate limiter status: {rate_limiter_status}")

    if rate_limiter_status['status'] == "blocked":
        authLog(f"[Login] Too many wrong attempts for email: {request.data.get('email', '')}" )
        return Response({
            "message": "Too many wrong attempts",
            "Please try again after": rate_limiter_status['time_left']
        }, status=429)
    
    authLog(f"[Login] Received data: {request.data}")

    email = request.data.get('email')
    input_passphrase = request.data.get('passphrase')

    serializer = UserLoginSerializer(data=request.data)
    if not serializer.is_valid():
        authLog("[login] Invalid data: %s", serializer.errors)
        return Response(serializer.errors, status=400)
    
    

    # check if email exists in the database
    user = User.objects.filter(email=email).first()
    if not user:
        authLog(f"[login] User with email {email} does not exist")
        rate_limiter_wrong_login(email)
        return Response({"message": "User does not exist",
                         "wrong_attemps": rate_limiter_status["current_requests"]  +1
                         }, status=404)
    # check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    print (f"[login] new_passphrase_data: {new_passphrase_data}")
    print (f"[login] user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        rate_limiter_wrong_login(email)
        authLog(f"[login] Invalid passphrase for user: {email}")
        return Response({"message": "Invalid credentials",
                         "wrong_attemps": rate_limiter_status["current_requests"] + 1
                         
                         }, status=401)
    
    # if account blocked
    if check_account_active(user):
        authLog(f"[login] Account for user {email} is blocked" )
        return Response({"message": "Account is blocked, please contact ADMIN for more info "}, status=403)
    
    # Send OTP to user's email
    otp = generate_otp(email)
    if not send_otp(email, otp):
        return Response({"message": "Failed to send OTP"}, status=500)

    # Lưu email vào session
    request.session['login_email'] = email
    request.session.set_expiry(300)  # Session expires after 5 minutes
    
    res = {
        "message": "OTP sent to your email",
        "email": email,
        "otp_expires_in": 300  # OTP expires in 5 minutes
    }
    
    redis_key = f"rate_limit:{email}"
    r.delete(redis_key)  # Reset rate limit counter on successful login attempt
    
    
    
    
    return Response(res, status=200)
    
    
@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    """
    This is a simple view that handles user registration.
    """
    authLog(f"[Register] Received data: {request.data}" )

    serializer = UserRegistrationSerializer(data=request.data)
    if not serializer.is_valid():
        authLog(f"[Register] Invalid data: {serializer.errors}", )
        return Response(serializer.errors, status=400)

    user = serializer.save()

    authLog(f"[Register] User registered successfully: {user.email}", )
    
    return Response({
            "message": "User registered successfully",
            "user_id": user.id,
            "name": user.name,
    }, status=201)
    



@api_view(['POST'])
@permission_classes([AllowAny])
def api_create_RSA_pair(request):
    
    private_key_pem, public_key_pem = generate_rsa_keys()
    
    input_passphrase = request.data.get('passphrase')
    user_id = request.data.get('user_id')
    
        # check if email exists in the database
        
    user = User.objects.filter(pk=user_id).first()
    if not user:
        keyLog(f"[api_create_RSA_pair] User with id {user_id} does not exist")
        return Response({"message": "User does not exist"}, status=404)
    
    # check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    keyLog (f"[api_create_RSA_pair][user_id {user_id}] new_passphrase_data: {new_passphrase_data}")
    keyLog (f"[api_create_RSA_pair][user_id {user_id}]  user.passphrase_hash: {user.passphrase_hash}")
    if new_passphrase_data['hash'] != user.passphrase_hash:
        keyLog(f"[api_create_RSA_pair] Invalid passphrase for user_id: {user_id}")
        return Response({"message": "Invalid credentials"}, status=401)
    
    # AES cipher private key
    private_key_enc = encrypt_private_with_passphrase(private_key_pem, input_passphrase, user.passphrase_salt.encode('utf-8'))
    public_key_pem_b64 = b64encode(public_key_pem).decode('utf-8')
    
    # change public_key_pem to json, add created_at and email
    public_key_pem_b64_final = json.dumps({
        "public_key": public_key_pem_b64,
        "created_at": now().isoformat(),
        "email": user.email
    })
    
    # Create Key object
    key = Key.objects.create(
        user=user,
        public_key=public_key_pem_b64_final,
        private_key_enc=private_key_enc
    )
    key.save()
    
    return Response({
        
        "message": "RSA key pair created successfully",
        "key_id": key.id,
        "user_id": user.id,
        "public_key": public_key_pem_b64_final,
        "expires_at": key.expires_at.isoformat()
    }, status=201)






@api_view(['POST'])
@permission_classes([AllowAny])
def api_otp_verify(request):
    serializer = OTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        authLog(f"[OTP] Invalid data: {serializer.errors}")
        return Response(serializer.errors, status=400)

    email = serializer.validated_data['email']
    otp = serializer.validated_data['otp']

    # Check session (comment when testing)
    # if email != request.session.get('login_email'):
    #     authLog(f"[OTP] Invalid session for {email}")
    #     return Response({"message": "Invalid session"}, status=401)

    # Check OTP in database
    latest_otp = OTP.objects.filter(email=email).order_by('-otp_created').first()
    if not latest_otp:
        authLog(f"[OTP] No OTP found for {email}")
        return Response({"message": "No OTP found"}, status=404)

    if now() > latest_otp.otp_expires:
        authLog(f"[OTP] Expired OTP for {email}")
        return Response({"message": "OTP expired"}, status=401)

    # Delete OTP and session
    del request.session['login_email']
    latest_otp.delete()

    user = User.objects.filter(email=email).first()
    if not user:
        authLog(f"[OTP] No user found for {email}")
        return Response({"message": "User not found"}, status=404)
    
    CustomToken.objects.filter(user=user).delete()
    token = CustomToken.objects.create(user=user, key=secrets.token_hex(20))

    authLog("[OTP] Successful login for {email}")

    return Response({
        "message": "Login successful",
        "user_id": user.id,
        "name": user.name,
        "token": token.key
    }, status=200)



@api_view(['POST'])
@permission_classes([AllowAny])
def api_update_user(request):
    """
    This is a simple view that handles user update.
    """
    profileLog(f"[Update User] Received data: {request.data}")

    user_id = request.data.get('user_id')
    name = request.data.get('name')
    phone_number = request.data.get('phone_number')
    address = request.data.get('address')
    birth_day = request.data.get('birth_day')

    user = User.objects.filter(pk=user_id).first()
    if not user:
        profileLog(f"[Update User][user_id {user_id}] User with id {user_id} does not exist")
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
            profileLog(f"[Update User][user_id {user_id}] Invalid date format for birth_day: {birth_day}")
            return Response({"message": "Invalid date format for birth_day"}, status=400)
    
    user.save()
    profileLog(f"[Update User][user_id {user_id}] User updated successfully: {user.email}")

    res = {
        "message": "User updated successfully",
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "phone_number": user.phone_number,
        "address": user.address,
    }

    # Handle passphrase change if provided
    curr_passphrase = request.data.get('current_passphrase')
    new_passphrase = request.data.get('new_passphrase')
    if curr_passphrase and new_passphrase:
        response = handle_passphrase_change(user_id, curr_passphrase, new_passphrase)
        profileLog(f"[Update User] Passphrase change response: {response}")

        if response != 1:
            return response
        else:
            res['message'] += " and passphrase changed successfully"

    return Response(res, status=200)
    
    
def handle_passphrase_change(user_id, input_passphrase, new_passphrase):
    user = User.objects.filter(pk=user_id).first()
    if not user:
        profileLog(f"[handle_passphrase_change] User with id {user_id} does not exist")
        return Response({"message": "User does not exist"}, status=404)
    
    # Check if passphrase is correct
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    if new_passphrase_data['hash'] != user.passphrase_hash:
        profileLog(f"[handle_passphrase_change] Invalid passphrase for user_id: {user_id}")
        return Response({"message": "Invalid credentials"}, status=401)
    
    # Decrypt all private keys of the user
    keys = Key.objects.filter(user=user)
    if not keys:
        profileLog(f"[handle_passphrase_change] No keys found for user_id: {user_id}")
        return Response({"message": "No keys found for user"}, status=404)
    
    # AES cipher private key
    new_salt = os.urandom(16)
    new_salt = b64encode(new_salt).decode('utf-8')  # Base64 encode the new salt | 5h for this shit
    # print (f"[handle_passphrase_change+++++] new_salt: {new_salt}")
    for key in keys:
        try:
            decrypt = decrypt_private_with_passphrase(key.private_key_enc, input_passphrase, user.passphrase_salt.encode('utf-8'))
            if decrypt is None:
                profileLog(f"[handle_passphrase_change] Failed to decrypt private key for user_id {user_id}")
                return Response({"error": "Error decrypting private keys"}, status=400)
            
            # Re-encrypt with new passphrase
            
            key.private_key_enc  = encrypt_private_with_passphrase(decrypt, new_passphrase, new_salt)
            key.save()
        except Exception as e:
            profileLog("[handle_passphrase_change] Error decrypting private key for user_id %s: %s", user_id, str(e))
            return Response({"message": "Error decrypting private keys"}, status=500)
        
    # Update user's passphrase salt and hash
    passphrase_data = hash_passphrase(new_passphrase, new_salt)
    user.passphrase_salt = passphrase_data['salt']
    user.passphrase_hash = passphrase_data['hash']
    user.save()

    return 1


@api_view(['POST'])
@permission_classes([AllowAny])
def api_send_encrypted_file(request):
    """
    This view handles sending an encrypted file to a recipient.
    """
    fileLog(f"[Send Encrypted File] Received data: {request.data}")

    file_path = request.data.get('file_path')
    sender_email = request.data.get('sender_email')
    recipient_email = request.data.get('recipient_email')
    output_path = request.data.get('output_path', None)
    mode = request.data.get('mode', "combined")

    if not file_path or not os.path.exists(file_path):
        fileLog(f"[Send Encrypted File] File does not exist: {file_path}")
        return Response({"message": "File does not exist"}, status=404)

    if not sender_email or not recipient_email:
        fileLog("[Send Encrypted File] Sender or recipient email is missing")
        return Response({"message": "Sender or recipient email is missing"}, status=400)
    
    fileLog(f"[Send Encrypted File] sender_email: {sender_email}, recipient_email: {recipient_email}, output_path: {output_path}, mode: {mode}, file_path: {file_path}")

    try:
        response = encrypt_file_with_metadata(file_path, sender_email, recipient_email, output_path=output_path, mode=mode)
        fileLog(f"[Send Encrypted File] Response from encrypt_file_with_metadata: {response}")
        
        if response is None:
            return Response({"message": "Error encrypting file"}, status=500)
        
        return response
    
    except Exception as e:
        fileLog(f"[Send Encrypted File] Unexpected error occurred: {str(e)}")
        return Response(
            {"detail": "An error occurred while encrypting the file.", "error": str(e)},
            status=500
        )

    
@api_view(['POST'])
@permission_classes([AllowAny])
def api_decrypt_file(request):
    """
    This view handles decrypting an encrypted file.
    """
    fileLog(f"[Decrypt File] Received data: {request.data}")

    encrypted_file_path = request.data.get('file_path')
    output_path = request.data.get('output_file_path', None)
    input_passphrase = request.data.get('passphrase', None)
    user_id = request.data.get('user_id', None)
    
    # Check passphrase
    user = User.objects.filter(pk=user_id).first()
    if not user:
        fileLog(f"[Decrypt File] User with id {user_id} does not exist")
        return Response({"message": "User does not exist"}, status=404)
    
    new_passphrase_data = hash_passphrase(input_passphrase, user.passphrase_salt)
    if new_passphrase_data['hash'] != user.passphrase_hash:
        fileLog(f"[Decrypt File] Invalid passphrase for user_id: {user_id}")
        return Response({"message": "Invalid credentials"}, status=401)

    fileLog(f"[Decrypt File] encrypted_file_path: {encrypted_file_path}, output_path: {output_path}")
    
    try:
        if not encrypted_file_path or not os.path.exists(encrypted_file_path):
            fileLog(f"[Decrypt File] Encrypted file does not exist: {encrypted_file_path}")
            return Response({"message": "Encrypted file does not exist"}, status=404)

        response = decrypt_file(input_passphrase=input_passphrase, f_input_enc=encrypted_file_path, f_output=output_path)
        
        if response is None:
            return Response({"message": "Error decrypting file"}, status=500)
        else:
            fileLog(f"[Decrypt File][user_id {user_id}] File decrypted successfully")
            return response

    except Exception as e:
        fileLog(f"[Decrypt File] Unexpected error occurred: {str(e)}")
        return Response(
            {"detail": "An error occurred while decrypting the file.", "error": str(e)},
            status=500
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
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
    keyLog(f"[Generate QR Code][user_id {user_id}]  QR data: {qr_data}")

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
@permission_classes([IsAuthenticated])
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
    
    

# 14
# find public key by email

# Hiển thị kết quả: email, QR code, ngày tạo, thời hạn còn lại/
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_public_key_by_email(request, email):
    """
    This view retrieves the public key for a given email.
    """
    keyLog(f"[Get Public Key] Received email: {email}")

    user = User.objects.filter(email=email).first()
    if not user:
        keyLog(f"[Get Public Key][email {email}] User with email {email} does not exist" )
        return Response({"message": "User does not exist"}, status=404)



    keys = Key.objects.filter(user=user.id).order_by('-created_at')
    if not keys:
        keyLog(f"[Get Public Key] User doesnt have any publickey {email}")
        return Response({"message": "User doesnt have any publickey"}, status=404)

    res = {}
    counter = 1
    for key in keys:
        status = "valid"
        if key.is_expired():
            logger.info("[Get Public Key] Key for user %s is expired", user.email)
            status = "expired"     
        safe_email = user.email.replace("@", "")  # loại bỏ @
        filename = f"qr_{safe_email}.png"
        qr_path = os.path.join("applications", "data", "qr_codes", filename)
        encoded_path = quote(qr_path)  
        qr_url = request.build_absolute_uri(f"/api/serve_jpg/?file_path={encoded_path}")
        res_key = {
            "public_key": key.public_key,
            "created_at": key.created_at.strftime("%d/%m/%Y %H:%M"),
            "expires_at": key.created_at.strftime("%d/%m/%Y %H:%M"),
            "status":status,
            "expiration_days": key.get_expiration_days(),
            "qr_code_url": qr_url
            
        }
        res[f"public_key_{counter}"] = res_key
        counter+=1

    return Response(res, status=200)



@api_view(['GET'])
@permission_classes([AllowAny])
def serve_jpg(request):
    raw_path = request.GET.get('file_path')
    print(f"[serve_jpg] Raw file_path: {raw_path}")

    if not raw_path:
        return Response({"error": "file_path is required"}, status=400)

    file_path = unquote(raw_path)
    print(f"[serve_jpg] Decoded file_path: {file_path}")

    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), content_type='image/jpeg')
    return Response({"error": f"File does not exist at path: {file_path}"}, status=404)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sign_file(request):
    try:
        if 'file' not in request.FILES:
            sigLog(f"User: {getattr(request.user, 'email', 'AnonymousUser')} - Action: Sign file - Status: Failed - Error: No file provided")
            return Response({"error": "Please provide file"}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']
        passphrase = request.data.get('passphrase')

        if not passphrase:
            sigLog(f"User: {getattr(request.user, 'email', 'AnonymousUser')} - Action: Sign file - Status: Failed - Error: No passphrase provided")
            return Response({"error": "Please provide passphrase"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_key = Key.objects.get(user=request.user)
            if user_key.is_expired():
                logging.info(f"User: {request.user.email} - Action: Sign file - Status: Failed - Error: Key expired")
                return Response({"error": "Your key has expired"}, status=status.HTTP_400_BAD_REQUEST)
        except Key.DoesNotExist:
            sigLog(f"User: {request.user.email} - Action: Sign file - Status: Failed - Error: No RSA key")
            return Response({"error": "You do not have an RSA key"}, status=status.HTTP_400_BAD_REQUEST)

        # read file and hash
        file_content = uploaded_file.read()
        file_hash = calculate_file_hash(file_content)

        # decrypt private key with passphrase
        try:
            salt = user_key.user.passphrase_salt.encode('utf-8')
            private_key_bytes = decrypt_private_with_passphrase(user_key.private_key_enc, passphrase, salt)
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
        except ValueError as e:
            sigLog(f"User: {request.user.email} - Action: Sign file - Status: Failed - Error: {str(e)}")
            return Response({"error": f"Passphrase is incorrect: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Sign file hash
        signature = sign_file_hash(file_hash, private_key)

        # Generate signer name
        first_name = getattr(request.user, 'first_name', '')
        last_name = getattr(request.user, 'last_name', '')
        username = getattr(request.user, 'username', '')
        email = getattr(request.user, 'email', '')

        signer_name = f"{first_name} {last_name}".strip() or username or email

        # Create signature data
        signature_data = {
            'file_name': uploaded_file.name,
            'file_hash': file_hash,
            'signature': signature,
            'signer_email': email,
            'signer_name': signer_name,
            'signed_at': timezone.now().isoformat(),
            'algorithm': 'RSA-PSS with SHA-256'
        }

        # Create signature file
        sig_dir = os.path.join(settings.BASE_DIR, 'applications', 'data', 'signatures')
        sig_file_path = create_signature_file(uploaded_file.name, signature_data, sig_dir)

        # Save digital signature to db
        DigitalSignature.objects.create(
            signer=request.user,
            file_name=uploaded_file.name,
            file_hash=file_hash,
            signature=signature,
            signature_file_path=sig_file_path
        )

        sigLog(f"User: {email} - Action: Sign file - Status: Success - File: {uploaded_file.name}")

        return Response({
            "message": "File signed successfully",
            "signature_file": os.path.basename(sig_file_path),
            "signature_data": signature_data
        }, status=status.HTTP_200_OK)

    except Exception as e:
        email = getattr(request.user, 'email', 'AnonymousUser')
        sigLog(f"User: {email} - Action: Sign file - Status: Failed - Error: {str(e)}")
        return Response({"error": f"Error signing file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_signature(request):
    try:
        if hasattr(request, 'user') and hasattr(request.user, 'email'):
            user_email = request.user.email
        else:
            user_email = 'AnonymousUser'

        if 'original_file' not in request.FILES or 'signature_file' not in request.FILES:
            sigLog(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Missing files")
            return Response({"error": "Please provide both the original file and the signature file."}, status=status.HTTP_400_BAD_REQUEST)
        
        original_file = request.FILES['original_file']
        signature_file = request.FILES['signature_file']
        
        if not signature_file.name.endswith('.sig'):
            sigLog(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Invalid signature file format")
            return Response({"error": "The signature file must have an extension .sig"}, status=status.HTTP_400_BAD_REQUEST)
        
        sig_content = signature_file.read().decode('utf-8')
        signature_data = json.loads(sig_content)
        
        original_content = original_file.read()
        original_hash = calculate_file_hash(original_content)
        
        if original_hash != signature_data['file_hash']:
            logging.info(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Hash mismatch")
            return Response({
                "verification_result": "invalid",
                "reason": "File has been modified"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            signer = User.objects.get(email=signature_data['signer_email'])
            signer_key = Key.objects.get(user=signer)
        except (User.DoesNotExist, Key.DoesNotExist):
            sigLog(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Public key not found")
            return Response({
                "verification_result": "invalid",
                "reason": "Public key not found"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        signer = User.objects.get(email=signature_data['signer_email'])
        signer_key = Key.objects.get(user=signer)
        print("Public Key in DB:")
        print(repr(signer_key.public_key))
        is_valid = verify_signature_with_public_key(signature_data['file_hash'], signature_data['signature'], signer_key.public_key)
        
        if is_valid:
            signer_name = f"{getattr(signer, 'first_name', '')} {getattr(signer, 'last_name', '')}".strip()
            if not signer_name:
                signer_name = getattr(signer, 'email', 'Unknown')


            logging.info(f"User: {user_email} - Action: Verify signature - Status: Success - File: {original_file.name}")
            return Response({
                "verification_result": "valid",
                "signature_data": signature_data,
                "signer_name": signer_name
            }, status=status.HTTP_200_OK)
        else:
            sigLog(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Invalid signature")
            return Response({
                "verification_result": "invalid",
                "reason": "Invalid signature"
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except json.JSONDecodeError:
        if hasattr(request, 'user') and hasattr(request.user, 'email'):
            user_email = request.user.email
        else:
            user_email = 'AnonymousUser'
        logging.info(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: Invalid signature file format")
        return Response({"error": "Signature file is not in correct format."}, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        if hasattr(request, 'user') and hasattr(request.user, 'email'):
            user_email = request.user.email
        else:
            user_email = 'AnonymousUser'        
        sigLog(f"User: {user_email} - Action: Verify signature - Status: Failed - Error: {str(e)}")
        return Response({"error": f"Error while verifying signature: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    

# Get email passphrase token
@api_view(['POST'])
@permission_classes([AllowAny])
def email_passphrase_token(request):
    email = request.data.get('email')
    passphrase = request.data.get('passphrase')

    user = User.objects.filter(email=email).first()
    if not user:
        return Response({"error": "Email does not exist"}, status=404)

    new_pass = hash_passphrase(passphrase, user.passphrase_salt)
    if new_pass['hash'] != user.passphrase_hash:
        return Response({"error": "Wrong passphrase"}, status=400)

    CustomToken.objects.filter(user=user).delete()

    token = CustomToken.objects.create(user=user, key=secrets.token_hex(20))

    return Response({"token": token.key})



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_list_accounts(request, user_id):
    """
    This view lists all accounts.
    """
    admin_user = User.objects.filter(id=user_id, role="Admin").first()
    if not admin_user:
        adminLog(f"[List Accounts] User with id {user_id} is not an admin", )
        return Response({"message": "You are not authorized to view this information"}, status=403)
    
    users = User.objects.all().order_by('-created_at')
    res = []
    for user in users:
        res.append({
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "phone_number": user.phone_number,
            "address": user.address,
            "birth_day": user.birth_day.strftime("%Y-%m-%d") if user.birth_day else None,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "role": user.role
        })
        
    return Response(res, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_change_account_status(request, user_id):
    """
    This view changes the status of an account.
    """
    target_id = request.data.get('target_id')
    new_status = request.data.get('new_status')
    
    admin_user = User.objects.filter(id=user_id, role="Admin").first()
    if not admin_user:
        adminLog(f"[Change Account Status] User with id {user_id} is not an admin")
        return Response({"message": "You are not authorized to change account status"}, status=403)
        
    if not target_id or not new_status:
        return Response({"message": "Missing user_id or status"}, status=400)
    
    user = User.objects.filter(id=target_id).first()
    if not user:
        return Response({"message": "User does not exist"}, status=404)
    
    if new_status not in User.AccountStatus.__members__:
        return Response({"message": "Invalid status"}, status=400)
    
    user.account_status = User.AccountStatus[new_status]
    user.save()
    adminLog(f"[Change Account Status] User {user.email} status changed to {new_status}")
    
    return Response({"message": f"User {user.email} status changed to {new_status}"}, status=200)



# 12 
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_encrypt_large_file(request):

    file = request.FILES.get('file')
    email = request.data.get('email')
    if not file or not email:
        fileLog(f"[Encrypt Large File][email {email}] Missing file or email")
        return Response({"message": "Missing file or email"}, status=400)

    upload_dir = os.path.join('applications', 'data', 'EncryptLargeFile', 'Upload')
    encrypted_dir = os.path.join('applications', 'data', 'EncryptLargeFile', 'Encrypted')
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(encrypted_dir, exist_ok=True)

    # save the uploaded file
    upload_file_path = os.path.join(upload_dir, file.name)
    
    try:
        with open(upload_file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)
        
        session_key = os.urandom(32)  
        result = encrypt_large_file(upload_file_path, email, session_key)
        
        if result['success']:
            fileLog(f"[Encrypt Large File][email {email}] File encryption successful: {file.name}")
            # Move the encrypted file to the encrypted directory
            final_output_path = os.path.join(encrypted_dir, f"{file.name}.enc")
            shutil.move(result['output_file'], final_output_path)
            return Response({
                "message": "File encryption successful",
                "output_file": final_output_path
            }, status=200)
        else:
            fileLog(f"[Encrypt Large File][email {email}] File encryption failed: {result.get('error', 'Unknown error')}")
            return Response({
                "message": "File encryption failed",
                "error": result.get('error', 'Unknown error')
            }, status=500)
    
    except Exception as e:
        logger.error(f"[Encrypt Large File][email {email}] Error processing file: {str(e)}")
        return Response({
            "message": "Error processing file",
            "error": str(e)
        }, status=500)

# 13
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_key_status(request, email):
    status_data = check_key_status(email)
    if status_data.get("status") == "Lỗi":
        actionLog(f"[Key Status][email {email}] Error checking lock status for {email}: {status_data.get('error')}")
        return Response({"message": "Error checking lock status", "error": status_data.get("error")}, status=500)
    logger.info(f"[Key Status] Lock status for {email}: {status_data['status']}")
    return Response(status_data, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_renew_key(request):
    email = request.data.get('email')
    passphrase = request.data.get('passphrase')
    if not email or not passphrase:
        actionLog(f"[Renew Key][email {email}] Missing email or passphrase")
        return Response({"message": "Missing email or passphrase"}, status=400)

    success = renew_key(email, passphrase)
    if success:
        actionLog(f"[Renew Key][email {email}] Key renewal successful {email}")
        return Response({"message": "Key renewal successful"}, status=200)
    actionLog(f"[Renew Key][email {email}] Key renewal failed for {email}")
    return Response({"message": "Key renewal failed for"}, status=500)
    
    
    
    