from rest_framework import viewsets, status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
import pyotp
from .models import MFAProfile, TrustedDevice, SecurityAlert, LoginAttempt
from .serializers import (
    UserSerializer, LoginSerializer, MFATokenSerializer,
    MFASetupSerializer, TrustedDeviceSerializer, SecurityAlertSerializer
)
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )

        if not user:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if user.is_account_locked and user.account_locked_until > timezone.now():
            return Response(
                {'error': 'Account is locked. Please try again later.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Record login attempt
        LoginAttempt.objects.create(
            user=user,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            was_successful=True
        )

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        tokens = {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }

        if user.is_mfa_enabled:
            request.session['mfa_user_id'] = user.id
            return Response({
                'message': 'MFA verification required',
                'requires_mfa': True,
                'temp_token': str(refresh.access_token)  # Token temporal para verificación MFA
            })

        login(request, user)
        return Response({
            'user': UserSerializer(user).data,
            'requires_mfa': False,
            'tokens': tokens
        })
    
class VerifyMFAView(generics.GenericAPIView):
    serializer_class = MFATokenSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = request.session.get("mfa_user_id")
        if not user_id:
            return Response(
                {"error": "No MFA session fund"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = User.objects.get(id=user_id)
        mfa_profile = user.mfa_profile

        if not mfa_profile.verify_totp(serializer.validated_data["token"]):
            return Response(
                {"error": "Invalid MFA token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if serializer.validated_data.get("trust_device"):
            TrustedDevice.objects.create(
                user=user,
                device_name=serializer.validated_data.get("device_name", "Unknown Device"),
                device_type=request.META.get("HTTP_USER_AGENT","unknown"),
                ip_address=request.META.get("REMOTE_ADDR")
            )
        
        login(request, user)
        del request.session['mfa_user_id']

        return Response({
            "message": "MFA verification successful",
            "user": UserSerializer(user).data
        })
    
class SetupMFAView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MFASetupSerializer

    def get(self, request):
        """Get MFA setup information"""
        if hasattr(request.user, "mfa_profile"):
            mfa_profile = request.user.mfa_profile
        else:
            mfa_profile = MFAProfile.objects.create(
                user=request.user,
                secret_key=pyotp.random_base32()
            )
        serializer = self.get_serializer(mfa_profile)
        return Response(serializer.data)
    
    def post(self, request):
        """Verify and activate MFA"""
        mfa_profile = request.user.mfa_profile
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not mfa_profile.verify_totp(serializer.validated_data['verification_code']):
            return Response(
                {"error": "Invalid verification code"},
                status=status.HTTP_400_BAD_REQUEST
            )

        mfa_profile.is_verified = True 
        mfa_profile.save()

        request.user.is_mfa_enabled = True 
        request.user.save()

        return Response({
            "message": "MFA setup successful",
            "is_verified": True 
        })

class TrustedDeviceViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = TrustedDeviceSerializer

    def get_queryset(self):
        return TrustedDevice.objects.filter(user=self.request.user)
    
class SecurityAlertViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = SecurityAlertSerializer

    def get_queryset(self):
        return SecurityAlert.objects.filter(user=self.request.user)

    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_mfa(request):
    user = request.user
    if not user.is_mfa_enabled:
        return Response(
            {"error": "MFA is not enabled"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user.is_mfa_enabled = False
    user.save()

    if hasattr(user, "mfa_profile"):
        user.mfa_profile.delete()

    return Response({"message":"MFA disabled successfully"})