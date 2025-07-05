import base64
from django.contrib.auth import get_user_model
from django.conf import settings
import time
from datetime import datetime, timezone
import hashlib
import hmac
import json
from functools import wraps
from rest_framework.response import Response


# jwt
import jwt
from jwt import InvalidTokenError
from django.conf import settings
import os

def return_msg(status_code, message, data=None):
    """
    Helper function to create a standardized JSON response.
    THIS IS THE CORRECT IMPLEMENTATION.
    """
    status_code = int(status_code)  # Ensure status_code is an integer
    print (f"🔍 Returning message with status {status_code}: {message}")
    response_data = {'message': message}
    if data:
        response_data.update(data)
    
    # The key is to return a JsonResponse object, not a dict.
    # return Response(response_data, status=status_code)
    return Response(response_data, status=status_code , content_type='application/json')



def jwt_required(view_func):
    @wraps(view_func)
    def verify_jwt_token(request):
        print("🔍 JWT token verification decorator applied")
        
        User = get_user_model()
        
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            print ("❗ Authorization header missing")
            return return_msg(401, "Authorization header missing")
        
        try:
            auth_type, token_str = auth_header.split()
            if auth_type.lower() != 'bearer':
                return return_msg(401, "Invalid authorization type, NOT Bearer")
            
        except ValueError:
            return return_msg(401, "Invalid authorization header format, NOT Bearer")
        
        # 2. split the token into 3 parts
        try :
            encoded_header, encoded_payload, encoded_signature = token_str.split('.')
        except ValueError:
            return return_msg(401, "Invalid JWT token format. Must contain three parts separated by dots.")
        
        payload = ""
        if (get_jwt_algorithm(encoded_header) == 'HS256'):
            # 3. Verify the signature using HS256
            print (f"🔍 Verifying JWT token with HS256 algorithm")
            payload = verify_hs256_signature(encoded_header, encoded_payload, encoded_signature)
        elif (get_jwt_algorithm(encoded_header) == 'RS256'):
            # 3. Verify the signature using RS256
            print (f"🔍 Verifying JWT token with RS256 algorithm")
            payload = verify_jwt_token_rs256(token_str)
            
    # 5. Check the 'exp' (expiration) claim
        if 'exp' not in payload:
            return return_msg(401, "JWT token missing 'exp' claim")
        
        try:
            expiration_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        except (ValueError, TypeError):
            
            return return_msg(401, "Invalid 'timestamp' in JWT token")
        
        if datetime.now(timezone.utc) > expiration_time:
            return return_msg(401, "JWT token has expired")    
        
        # if payload does not contain user_id, ????
        user_id = payload.get('user_id')    
        if user_id is None:
            
            return return_msg(401, "Token is missing the user identifier")    
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return return_msg(401, f"User with ID {user_id} does not exist")    
        
        print (f"🔍 JWT token is valid for user: {user.username} (ID: {user.id})")
        
        request.user = user
        return view_func(request)
        
    return verify_jwt_token
    
    
def verify_hs256_signature(encoded_header, encoded_payload, encoded_signature):
        # recreate signature for comparison
    unsigned_token = (encoded_header + '.' + encoded_payload).encode('utf-8')
    secret_key = settings.SECRET_KEY.encode('utf-8')
    # secret_key = "mycustomsecretkey".encode('utf-8')
    expected_signature = hmac.new(secret_key, unsigned_token, hashlib.sha256).digest()
    # Decode the signature provided by the client
    try:
        padding = '=' * (-len(encoded_signature) % 4)
        received_signature = base64.urlsafe_b64decode(encoded_signature + padding)
    except Exception:
        return return_msg(401, "Invalid base64url encoding in signature")
    
    
    # compare the signatures
    if not hmac.compare_digest(expected_signature, received_signature):
        return return_msg(401, "Invalid JWT token signature")
        # 4. Decode the payload and validate its claims
        # ------------------------------------------------
    try:
        padding = '=' * (-len(encoded_payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(encoded_payload + padding)
        payload = json.loads(decoded_payload)
    except Exception as e:
        return return_msg(401, "Invalid base64url encoding in payload")
    return payload


def verify_jwt_token_rs256(token):
    try:
        key_path = os.path.join(settings.BASE_DIR, 'public.key')
        with open(key_path, 'r') as f:
            public_key = f.read()

        # Decode and verify the token using the public key and RS256 algorithm
        payload = jwt.decode(token, public_key, algorithms=['RS256'])

        # ✅ Valid token — return payload
        return payload

    except InvalidTokenError as e:
        # ❌ Invalid token
        print(f"Token verification failed: {str(e)}")
        return_msg(401, "Invalid JWT token")
        
        
def pad_b64(s): return s + '=' * (-len(s) % 4)

def get_jwt_algorithm(encoded_header):
    decoded_header_json = base64.urlsafe_b64decode(pad_b64(encoded_header)).decode('utf-8')
    header = json.loads(decoded_header_json)
    return header.get('alg')