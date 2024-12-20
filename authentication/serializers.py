from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.core.validators import EmailValidator
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
from .models import TrustedDevice, SecurityAlert, MFAProfile
import re 

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'is_mfa_enabled')
        read_only_fields = ('id', 'is_mfa_enabled')

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )

            if not user:
                msg = 'Invalid credentials'
                raise serializers.ValidationError(msg, code='authorization')
            
            if not user.is_active:
                msg = 'User account is disabled'
                raise serializers.ValidationError(msg, code='authorization')

        else:
            msg = 'Must include "username" and "password"'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class MFATokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    request_meta = serializers.DictField(required=False)

class MFASetupSerializer(serializers.Serializer):
    verification_code = serializers.CharField(max_length=6, min_length=6)

class TrustedDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustedDevice
        fields = ('id', 'device_name', 'device_type', 'last_used_at', 'is_active')
        read_only_fields = ('id', 'last_used_at')

class SecurityAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityAlert
        fields = ('id', 'timestamp', 'alert_type', 'severity', 'message', 'is_resolved')
        read_only_fields = ('id', 'timestamp')

class LoginResponseSerializer(serializers.Serializer):
    requires_mfa = serializers.BooleanField()
    session_id = serializers.UUIDField(required=False)
    user = UserSerializer()
    tokens = serializers.DictField(required=False)

class MFAVerificationSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6, min_length=6)
    session_id = serializers.UUIDField()
    device_info = serializers.DictField(required=False)

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm')

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError('Username already exists')
        return value

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError('Email already registered')
        return value.lower()

    def validate_password(self, value):
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', value):
            raise serializers.ValidationError(
                'Password must contain at least 8 characters, including letters, numbers and special characters'
            )
        return value

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({'password_confirm': "Passwords don't match"})
        return data