from rest_framework import viewsets, status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view

from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import (
    MFAProfile, 
    TrustedDevice, 
    SecurityAlert, 
    LoginAttempt
)
from .serializers import (
    UserSerializer, 
    LoginSerializer, 
    MFATokenSerializer,
    MFASetupSerializer, 
    TrustedDeviceSerializer, 
    SecurityAlertSerializer
)
from .services.mfa_service import MFASecurityService

User = get_user_model()

class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        login(request, user)  

        if user.is_mfa_enabled:
            request.session['mfa_user_id'] = user.id
            request.session['mfa_session_active'] = True
            request.session.modified = True  # Forzar guardado de sesión
            
            temp_token = RefreshToken.for_user(user)
            
            return Response({
                'requires_mfa': True,
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(temp_token.access_token)
                }
            })

        # Login normal sin MFA
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
        mfa_service = MFASecurityService(request.user)
        setup_data = mfa_service.setup_mfa()
        
        return Response({
            'qr_code': setup_data['qr_code'],
            'manual_entry_key': setup_data['manual_entry_key'],
            'message': 'Scan the QR code with Google Authenticator or enter the key manually'
        })

    def post(self, request):
        """Verificar y activar MFA"""
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

        # Generar códigos de respaldo
        backup_codes = mfa_service.generate_backup_codes()

        return Response({
            'message': 'MFA setup successful',
            'is_verified': True,
            'backup_codes': backup_codes,
            'warning': 'Save these backup codes securely. They will not be shown again.'
        })

class VerifyMFAView(generics.GenericAPIView):
    serializer_class = MFATokenSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Obtener el token del header de autorización
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response(
                {'error': 'Invalid authorization header'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        token = auth_header.split(' ')[1]
        
        try:
            # Decodificar el token temporal para obtener el user_id
            from rest_framework_simplejwt.tokens import AccessToken
            decoded_token = AccessToken(token)
            user_id = decoded_token['user_id']
            
            user = User.objects.get(id=user_id)
            mfa_service = MFASecurityService(user)

            # Verificar el token MFA
            is_valid, error = mfa_service.verify_token(
                serializer.validated_data['token'],
                serializer.validated_data.get('request_meta', {})
            )

            if not is_valid:
                return Response(
                    {'error': error or 'Invalid token'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Generar tokens finales
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

        except (User.DoesNotExist, Exception) as e:
            return Response(
                {'error': str(e)},
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