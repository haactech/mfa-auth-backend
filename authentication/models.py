from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator
import pyotp
from django.conf import settings
import uuid

class User(AbstractUser):
    """
    Extended User model with additional fields for MFA and security
    """
    phone_number = models.CharField(max_length=15, blank=True)
    is_mfa_enabled = models.BooleanField(default=False)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    is_account_locked = models.BooleanField(default=False)
    account_locked_until = models.DateTimeField

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")

class MFAProfile(models.Model):
    """
    Stores MFA-related information for each user
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="mfa_profile"
    )
    secret_key = models.CharField(
        max_length=32,
        validators=[MinLengthValidator(16)],
        unique=True
    )
    backup_codes = models.JSONField(default=list)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def generate_totp_secret(self):
        """Generate a new TOTP secret key"""
        return pyotp.random_base32()
    
    def verify_totp(self,token):
        """ Verify a TOTP token"""
        totp = pyotp.TOTP(self.secret_key)
        return totp.verify(token)
    
    def get_qr_code_url(self):
        """Generate QR code URL for TOTP setup"""
        totp = pyotp.TOTP(self.secret_key)
        return totp.provisioning_uri(
            name=self.user.email,
            issuer_name=settings.MFA_ISSUER_NAME
        )
    
class TrustedDevice(models.Model):
    """
    Stores information about devices that users have marked as trusted
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="trusted_devices"
    )
    device_id = models.UUIDField(default=uuid.uuid4(), unique=True)
    device_name = models.CharField(max_length=100)
    device_type = models.CharField(max_length=50)
    last_used_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()

class LoginAttempt(models.Model):
    """
    Records all login attempts for security monitoring
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="login_attempts"
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    was_successful = models.BooleanField()
    failure_reason = models.CharField(max_length=100, blank=True)
    location_info = models.JSONField(null=True)

class SecurityAlert(models.Model):
    """
    Stores security-related alerts and notifications
    """
    SEVERITY_CHOICES = [
        ("LOW","Low"),
        ("MEDIUM","Medium"),
        ("HIGH","High"),
        ("CRITICAL","Critical"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="security_alerts"
    )
    timestamp = models.DateTimeField(auto_now=True)
    alert_type = models.CharField(max_length=50)
    severity = models.CharField(
        max_length=8,
        choices=SEVERITY_CHOICES,
        default="LOW"
    )
    message = models.TextField()
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    related_ip = models.GenericIPAddressField(null=True, blank=True)
