from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import VerificationCode
import datetime

User = get_user_model()

class UserModelTests(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User',
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_create_user(self):
        """Test creating a user"""
        self.assertEqual(self.user.email, self.user_data['email'])
        self.assertEqual(self.user.first_name, self.user_data['first_name'])
        self.assertEqual(self.user.last_name, self.user_data['last_name'])
        self.assertTrue(self.user.check_password(self.user_data['password']))
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)
        self.assertFalse(self.user.email_verified)
        self.assertFalse(self.user.kyc_verified)

    def test_create_superuser(self):
        """Test creating a superuser"""
        admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        self.assertEqual(admin_user.email, 'admin@example.com')
        self.assertTrue(admin_user.is_active)
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)
        self.assertTrue(admin_user.email_verified)

    def test_user_str_representation(self):
        """Test the string representation of a user"""
        self.assertEqual(str(self.user), self.user_data['email'])

    def test_verification_code_generation(self):
        """Test verification code generation"""
        code = VerificationCode.generate_code(self.user)
        self.assertEqual(len(code.code), 6)
        self.assertEqual(code.user, self.user)
        self.assertFalse(code.is_used)
        self.assertEqual(code.purpose, 'email_verification')
        
        # Check that the expiry time is set correctly (24 hours from now)
        time_diff = code.expires_at - timezone.now()
        self.assertGreater(time_diff, datetime.timedelta(hours=23))
        self.assertLess(time_diff, datetime.timedelta(hours=25))

    def test_verification_code_is_valid(self):
        """Test verification code validity check"""
        # Valid code
        code = VerificationCode.generate_code(self.user)
        self.assertTrue(code.is_valid())
        
        # Used code
        code.is_used = True
        code.save()
        self.assertFalse(code.is_valid())
        
        # Expired code
        code.is_used = False
        code.expires_at = timezone.now() - datetime.timedelta(hours=1)
        code.save()
        self.assertFalse(code.is_valid())

    def test_verification_code_str_representation(self):
        """Test the string representation of a verification code"""
        code = VerificationCode.generate_code(self.user)
        expected_str = f"{code.code} for {self.user.email} (email_verification)"
        self.assertEqual(str(code), expected_str)