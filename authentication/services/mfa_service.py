from typing import Tuple,Optional,Dict
import pyotp
import base64
from io import BytesIO
from django.conf import settings
from datetime import datetime, timedelta
import qrcode.constants
from ..models import MFAProfile, SecurityAlert, LoginAttempt

class MFASecurityService:
    """
    Service class for handling MFA-related operations and security checks
    """
    MAX_FAILTED_ATTEMPTS = 3
    LOCK_DURATION = timedelta(minutes=30)

    def __init__(self, user):
        self.user = user 
        self.mfa_profile = getattr(user,"mfa_profile", None)

    def setup_mfa(self) -> Dict:
        """
        Initialize MFA setup for a user
        Returns: Dict containing secret and QR code
        """
        if not self.mfa_profile:
            secret = pyotp.random_base32()
            self.mfa_profile = MFAProfile.objects.create(
                user=self.user,
                secret_key=secret
            )
        else:
            secret = self.mfa_profile.secret_key

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            self.user.email,
            issuer_name=settings.MFA_ISSUER_NAME
        )

        #Generate QR code 
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode()

        return {
            "secret_key": secret,
            "qr_code": qr_code,
            "manual_entry_key": secret
        }
    
    def verify_token(self, token: str, request_meta: dict) -> Tuple[bool, Optional[str]]:
        """
        Verify MFA token and handle security checks
        Returns: Tuple(is_valid:bool, error_message: Optional[str])
        """
        if not self.mfa_profile:
            return False, "MFA not set up for this user"
        
        if self._is_account_locked():
            return False, "Account is temporarily locked due to too many failed attempts"
        
        totp = pyotp.TOTP(self.mfa_profile.secret_key)
        is_valid = totp.verify(token)

        self._record_verification_attempt(
            is_valid,
            request_meta.get("REMOTE_ADDR"),
            request_meta.get("HTTP_USER_AGENT")
        )

        if not is_valid:
            self._handle_failed_attempt()
            return False, "Invalid token"
        
        return True, None 
    
    def _is_account_locked(self) -> bool:
        """Check if account is currently locked"""
        if not self.user.account_locked_until:
            return False 
        current_time = datetime.now(self.user.account_locked_until.tzinfo)
        return self.user.account_locked_until > current_time
    
    def _handle_failed_attempt(self):
        """Handle failed verification attempt"""
        from django.utils import timezone

        self.user.failed_login_attempts += 1
        if self.user.failed_login_attempts >= self.MAX_FAILED_ATTEMPTS:
            self.user.is_account_locked = True
            self.user.account_locked_until = timezone.now() + self.LOCK_DURATION
            
            SecurityAlert.objects.create(
                user=self.user,
                alert_type='MFA_FAILED_ATTEMPTS',
                severity='HIGH',
                message=f'Account locked after {self.MAX_FAILED_ATTEMPTS} failed MFA attempts'
            )
        self.user.save()

    def _record_verification_attempt(self, was_successful: bool, ip_address: str, user_agent: str):
        """Record MFA verification attempt"""
        LoginAttempt.objects.create(
            user=self.user,
            ip_address=ip_address,
            user_agent=user_agent,
            was_successful=was_successful,
            failure_reason='Invalid MFA token' if not was_successful else ''
        )

    def generate_backup_codes(self, count: int = 8) -> list:
        """Generate new backup codes for the user"""
        if not self.mfa_profile:
            raise ValueError("MFA must be set up before generating backup codes")
            
        codes = [pyotp.random_base32()[:8] for _ in range(count)]
        self.mfa_profile.backup_codes = codes
        self.mfa_profile.save()
        return codes

    def verify_backup_code(self, code: str) -> bool:
        """Verify a backup code and remove it if valid"""
        if not self.mfa_profile or not self.mfa_profile.backup_codes:
            return False
            
        if code in self.mfa_profile.backup_codes:
            self.mfa_profile.backup_codes.remove(code)
            self.mfa_profile.save()
            return True
        return False
