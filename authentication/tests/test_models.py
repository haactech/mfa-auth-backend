from django.test import TestCase
from django.contrib.auth import get_user_model
from ..models import MFAProfile, AuthenticationSession
import pyotp

User = get_user_model()

class ModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.mfa_profile = MFAProfile.objects.create(
            user=self.user,
            secret_key=pyotp.random_base32()
        )

    def test_mfa_profile_creation(self):
        self.assertEqual(self.mfa_profile.user, self.user)
        self.assertTrue(len(self.mfa_profile.secret_key) >= 16)
        self.assertFalse(self.mfa_profile.is_verified)

    def test_totp_verification(self):
        totp = pyotp.TOTP(self.mfa_profile.secret_key)
        valid_token = totp.now()
        self.assertTrue(self.mfa_profile.verify_totp(valid_token))
        self.assertFalse(self.mfa_profile.verify_totp('000000'))

class AuthenticationSessionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_session_creation_and_validation(self):
        session = AuthenticationSession.create_session(
            user=self.user,
            device_info={'user_agent': 'test-agent'}
        )
        
        self.assertTrue(session.is_valid())
        self.assertFalse(session.is_mfa_completed)
        
        session.complete_mfa()
        self.assertTrue(session.is_mfa_completed)