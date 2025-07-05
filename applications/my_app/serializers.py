# Serializers define the API representation.
from rest_framework import serializers
from .models import User, Key

from applications.commons.utils import validate_passphrase_email, hash_passphrase


class UserRegistrationSerializer(serializers.ModelSerializer):
    passphrase = serializers.CharField(write_only=True, required=True, min_length=8, max_length=128)
    
    

    class Meta:
        model = User
        # Fields to be used for serialization/deserialization
        fields = ('id', 'name', 'email', 'birth_day', 'phone_number', 'address', 'role','passphrase')

    def validate(self, data):

        passphrase = data.get('passphrase')
        email = data.get('email')
        
        try :
            validate_passphrase_email(passphrase, email)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({"[ERROR]: validate_passphrase_email ": str(e)})

        return data

    def create(self, validated_data):
        # create salt and hash for passphrase
        passphrase = validated_data.pop('passphrase')
        passphrase_data = hash_passphrase(passphrase)
        
        # passphrase_salt = models.TextField()  # Base64 encoded
        # passphrase_hash = models.TextField()  # SHA-256 hash
        validated_data['passphrase_salt'] = passphrase_data['salt']
        validated_data['passphrase_hash'] = passphrase_data['hash']
        
        
        user = User.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],

            phone_number=validated_data['phone_number'],
            birth_day=validated_data['birth_day'],
            address=validated_data['address'],
            role=validated_data.get('role', User.Role.USER),  # Default to USER if not provided
            
            passphrase_salt = validated_data['passphrase_salt'],
            passphrase_hash = validated_data['passphrase_hash'],
            
        )
        return user
    
class UserLoginSerializer(serializers.Serializer):
    passphrase = serializers.CharField(write_only=True, required=True, min_length=8, max_length=128)
    email = serializers.EmailField(write_only=True, required=True)
    class Meta:
        fields = ('id', 'name', 'email', 'birth_day', 'phone_number', 'address', 'role','passphrase')

        
    def validate(self, data):

        passphrase = data.get('passphrase')
        email = data.get('email')
        
        try :
            validate_passphrase_email(passphrase, email)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({"[ERROR]: validate_passphrase_email ": str(e)})

        return data
    
