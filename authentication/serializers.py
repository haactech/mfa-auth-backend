from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import MFAProfile, TrustedDevice, SecurityAlert, LoginAttempt

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ("id","username","email","is_mfa_enabled")
        read_only_fields = ("id", "is_mfa_enabled")

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

class MFATokenSerializer(serializers.Serializer):
    token = serializers.CharField(min_length=6, max_length=6)

class MFASetupSerializer(serializers.ModelSerializer):
    qr_code_url = serializers.SerializerMethodField()
    verification_code = serializers.CharField(write_only=True,required=False)

    class Meta:
        model = MFAProfile
        fields = ("secret_key", "qr_code_url", "verification_code", "is_verified")
        read_only_fields = ("secret_key", "is_verified")

    def get_qr_code_url(self,obj):
        return obj.get_qr_code_url()
    
class TrustedDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustedDevice
        fields = ("device_id", "device_name", "device_type", "last_used_at")
        read_only_fields = ("device_id", "last_used_at")

class SecurityAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityAlert
        fields = "__all__"
        read_only_fields = ("user","timestamp")
