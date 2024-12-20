from rest_framework import viewsets, status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from .services.email_service import EmailService
from django.http import JsonResponse
from .services.email_service import EmailService

from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import (
    AuthenticationSession, 
    TrustedDevice, 
    SecurityAlert,
    EmailVerification
)
from .serializers import (
    UserSerializer, 
    LoginSerializer, 
    MFASetupSerializer, 
    TrustedDeviceSerializer, 
    SecurityAlertSerializer,
    MFAVerificationSerializer,
    SignupSerializer
)
from .services.mfa_service import MFASecurityService

User = get_user_model()

class SignupView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        #Crear usuario
        user = User.objects.create_user(
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password'],
            is_active=False
        )

        verification = EmailVerification.objects.create(user=user)

        EmailService.send_verification_email(user, verification.token)

        return Response({
            'message': 'Registration successful. Please check your email to verify your account.',
            'username': user.username,
            'email': user.email
        }, status=status.HTTP_201_CREATED)
    
@api_view(['GET'])
@permission_classes([AllowAny])

def verify_email(request, token):
    try:
        verification = EmailVerification.objects.get(token=token, is_verified=False)
        
        # Verificar y activar usuario
        verification.verify()
        
        return Response({
            'message': 'Email verified successfully. You can now login.',
        })
    except EmailVerification.DoesNotExist:
        return Response({
            'error': 'Invalid or expired verification token'
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        user.refresh_from_db()

        # Crear sesión temporal
        device_info = {
            'ip': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT')
        }
        auth_session = AuthenticationSession.create_session(
            user=user,
            device_info=device_info
        )

        if user.is_mfa_enabled:
            return Response({
                'requires_mfa': True,
                'session_id': auth_session.session_id,
                'user': UserSerializer(user).data
            })

        # Usuario sin MFA, completar sesión y generar tokens
        auth_session.complete_mfa()
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'requires_mfa': False,
            'user': UserSerializer(user).data,
            'tokens': {
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }
        })
class SetupMFAView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MFASetupSerializer

    def get(self, request):
        """Iniciar configuración MFA"""
        if request.user.is_mfa_enabled:
            return Response(
                {'error': 'MFA already configured'},
                status=status.HTTP_400_BAD_REQUEST
            )

        mfa_service = MFASecurityService(request.user)
        setup_data = mfa_service.setup_mfa()
        
        return Response({
            'qr_code': setup_data['qr_code'],
            'manual_entry_key': setup_data['manual_entry_key'],
            'message': 'Scan the QR code with Google Authenticator or enter the key manually'
        })

    def post(self, request):
        """Verificar y activar MFA"""
        if request.user.is_mfa_enabled:
            return Response(
                {'error': 'MFA already configured'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        mfa_service = MFASecurityService(request.user)
        is_valid, error = mfa_service.verify_token(
            serializer.validated_data['verification_code'],
            request.META
        )

        if not is_valid:
            return Response(
                {'error': error or 'Invalid verification code'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Activar MFA
        request.user.is_mfa_enabled = True
        request.user.save()

        # Generar códigos de respaldo
        backup_codes = mfa_service.generate_backup_codes()

        return Response({
            'message': 'MFA setup successful',
            'is_verified': True,
            'backup_codes': backup_codes,
            'warning': 'Save these backup codes securely. They will not be shown again.'
        })
    
@api_view(['GET'])
@permission_classes([AllowAny])
def test_email_config(request):
    try:
        # Crear una instancia del servicio de email
        email_service = EmailService()
        
        # Intentar enviar un email de prueba
        success = email_service.send_email(
            to_email="adanhermes23@gmail.com",  # Reemplaza con tu email
            subject="Test Email Configuration",
            template_name="account_verification",  # Usa una de las plantillas que creamos
            context={
                "user": {"username": "TestUser"},
                "verification_url": "http://example.com",
                "site_name": "Test Site"
            }
        )
        
        if success:
            return JsonResponse({
                "status": "success",
                "message": "Email sent successfully"
            })
        else:
            return JsonResponse({
                "status": "error",
                "message": "Failed to send email"
            }, status=500)
            
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

class VerifyMFAView(generics.GenericAPIView):
    serializer_class = MFAVerificationSerializer
    permission_classes = [AllowAny]

    def get_client_ip(self, request):
        """Obtaining ips even with proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or '0.0.0.0'

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            auth_session = AuthenticationSession.objects.get(
                session_id=serializer.validated_data['session_id']
            )

            if not auth_session.is_valid():
                return Response(
                    {'error': 'Session expired or invalid'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = auth_session.user
            mfa_service = MFASecurityService(user)

            device_info = serializer.validated_data.get('device_info',{})
            device_info['ip_address'] = self.get_client_ip(request)

            is_valid, error = mfa_service.verify_token(
                serializer.validated_data['token'],
                device_info
            )

            if not is_valid:
                return Response(
                    {'error': error or 'Invalid token'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # MFA verificado exitosamente
            auth_session.complete_mfa()
            
            # Generar tokens JWT finales
            refresh = RefreshToken.for_user(user)
            tokens = {
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }

            return Response({
                'message': 'MFA verification successful',
                'user': UserSerializer(user).data,
                'tokens': tokens
            })

        except AuthenticationSession.DoesNotExist:
            return Response(
                {'error': 'Invalid session'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
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

@ensure_csrf_cookie
@api_view(['GET'])
def get_csrf_token(request):
    token = get_token(request)
    return Response({'csrfToken': token})

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