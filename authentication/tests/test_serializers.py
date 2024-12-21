from django.test import TestCase
from django.contrib.auth import get_user_model
from ..serializers import UserSerializer, LoginSerializer

User = get_user_model()

class SerializerTests(TestCase):
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_user_serializer(self):
        serializer = UserSerializer(instance=self.user)
        self.assertEqual(serializer.data['username'], self.user_data['username'])
        self.assertEqual(serializer.data['email'], self.user_data['email'])
        self.assertFalse(serializer.data['is_mfa_enabled'])

    def test_login_serializer_validation(self):
        valid_data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        serializer = LoginSerializer(data=valid_data)
        self.assertTrue(serializer.is_valid())

        invalid_data = {
            'username': 'testuser',
            'password': 'wrongpass'
        }
        serializer = LoginSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())