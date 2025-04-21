
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from users.models import VerificationCode
from django.utils import timezone
import json

User = get_user_model()

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.verify_email_url = reverse('verify_email')
        self.resend_verification_url = reverse('resend_verification')
        self.profile_url = reverse('profile')
        self.change_password_url = reverse('change_password')
        self.token_refresh_url = reverse('token_refresh')
        self.health_url = reverse('health')
        
        # Test user data
        self.user_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword123',
            'password2': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '1234567890',
            'date_of_birth': '1990-01-01',
            'address': '123 Test St'
        }
        
        # Create a verified user for some tests
        self.verified_user = User.objects.create_user(
            email='verified@example.com',
            password='verifiedpass123',
            first_name='Verified',
            last_name='User',
            email_verified=True
        )

    def test_health_check(self):
        """Test the health check endpoint"""
        response = self.client.get(self.health_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'healthy')

    def test_user_registration(self):
        """Test user registration"""
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertIn('message', response.data)
        
        # Check that user was created in database
        self.assertTrue(User.objects.filter(email=self.user_data['email']).exists())
        
        # Check that verification code was created
        user = User.objects.get(email=self.user_data['email'])
        self.assertTrue(VerificationCode.objects.filter(user=user).exists())
        
        # Check that last_token_issued_at was updated
        self.assertIsNotNone(user.last_token_issued_at)

    def test_registration_with_mismatched_passwords(self):
        """Test registration with mismatched passwords"""
        data = self.user_data.copy()
        data['password2'] = 'differentpassword'
        
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_with_existing_email(self):
        """Test registration with an email that already exists"""
        # First registration
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Second registration with same email
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_verification(self):
        """Test email verification"""
        # Register a user first
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Get the verification code
        user = User.objects.get(email=self.user_data['email'])
        verification = VerificationCode.objects.filter(user=user).first()
        
        # Store the initial token timestamp
        initial_token_time = user.last_token_issued_at
        
        # Verify email
        verification_data = {
            'email': self.user_data['email'],
            'code': verification.code
        }
        
        response = self.client.post(self.verify_email_url, verification_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        
        # Check that user is now verified
        user.refresh_from_db()
        self.assertTrue(user.email_verified)
        
        # Check that verification code is now used
        verification.refresh_from_db()
        self.assertTrue(verification.is_used)
        
        # Check that last_token_issued_at was updated
        self.assertIsNotNone(user.last_token_issued_at)
        self.assertNotEqual(initial_token_time, user.last_token_issued_at)

    def test_email_verification_with_invalid_code(self):
        """Test email verification with invalid code"""
        # Register a user first
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Try to verify with invalid code
        verification_data = {
            'email': self.user_data['email'],
            'code': 'INVALID'
        }
        
        response = self.client.post(self.verify_email_url, verification_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Check that user is still not verified
        user = User.objects.get(email=self.user_data['email'])
        self.assertFalse(user.email_verified)

    def test_email_verification_with_expired_code(self):
        """Test email verification with expired code"""
        # Register a user first
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Get the verification code and make it expired
        user = User.objects.get(email=self.user_data['email'])
        verification = VerificationCode.objects.filter(user=user).first()
        verification.expires_at = timezone.now() - timezone.timedelta(hours=1)
        verification.save()
        
        # Try to verify with expired code
        verification_data = {
            'email': self.user_data['email'],
            'code': verification.code
        }
        
        response = self.client.post(self.verify_email_url, verification_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Check that user is still not verified
        user.refresh_from_db()
        self.assertFalse(user.email_verified)

    def test_login_with_verified_user(self):
        """Test login with a verified user"""
        # Store the initial token timestamp
        initial_token_time = self.verified_user.last_token_issued_at
        
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['message'], 'Login successful.')
        self.assertTrue(response.data['email_verified'])
        
        # Check that last_token_issued_at was updated
        self.verified_user.refresh_from_db()
        self.assertIsNotNone(self.verified_user.last_token_issued_at)
        if initial_token_time:
            self.assertNotEqual(initial_token_time, self.verified_user.last_token_issued_at)

    def test_login_with_unverified_user(self):
        """Test login with an unverified user"""
        # Register a user first
        self.client.post(self.register_url, self.user_data, format='json')
        
        user = User.objects.get(email=self.user_data['email'])
        initial_token_time = user.last_token_issued_at
        
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertIn('Your email is not verified', response.data['message'])
        self.assertFalse(response.data['email_verified'])
        
        # Check that a new verification code was created
        user = User.objects.get(email=self.user_data['email'])
        self.assertEqual(VerificationCode.objects.filter(user=user).count(), 2)
        
        # Check that last_token_issued_at was updated
        user.refresh_from_db()
        self.assertIsNotNone(user.last_token_issued_at)
        self.assertNotEqual(initial_token_time, user.last_token_issued_at)

    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_resend_verification(self):
        """Test resending verification code"""
        # Register a user first
        self.client.post(self.register_url, self.user_data, format='json')
        
        resend_data = {
            'email': self.user_data['email']
        }
        
        response = self.client.post(self.resend_verification_url, resend_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        
        # Check that a new verification code was created
        user = User.objects.get(email=self.user_data['email'])
        self.assertEqual(VerificationCode.objects.filter(user=user).count(), 2)

    def test_resend_verification_for_verified_user(self):
        """Test resending verification code for already verified user"""
        resend_data = {
            'email': 'verified@example.com'
        }
        
        response = self.client.post(self.resend_verification_url, resend_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Your email is already verified', response.data['message'])

    def test_resend_verification_for_nonexistent_user(self):
        """Test resending verification code for non-existent user"""
        resend_data = {
            'email': 'nonexistent@example.com'
        }
        
        response = self.client.post(self.resend_verification_url, resend_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_user_profile(self):
        """Test getting user profile"""
        # Login first to get token
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Get profile
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'verified@example.com')
        self.assertEqual(response.data['first_name'], 'Verified')
        self.assertEqual(response.data['last_name'], 'User')
        self.assertTrue(response.data['email_verified'])

    def test_update_user_profile(self):
        """Test updating user profile"""
        # Login first to get token
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Update profile
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'phone_number': '9876543210'
        }
        
        response = self.client.patch(self.profile_url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        self.assertEqual(response.data['phone_number'], '9876543210')
        
        # Check that user was updated in database
        user = User.objects.get(email='verified@example.com')
        self.assertEqual(user.first_name, 'Updated')
        self.assertEqual(user.last_name, 'Name')
        self.assertEqual(user.phone_number, '9876543210')

    def test_change_password(self):
        """Test changing password"""
        # Login first to get token
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Get the initial token timestamp
        user = User.objects.get(email='verified@example.com')
        initial_token_time = user.last_token_issued_at
        
        # Change password
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_data = {
            'old_password': 'verifiedpass123',
            'new_password': 'newpassword456',
            'new_password2': 'newpassword456'
        }
        
        response = self.client.post(self.change_password_url, password_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        
        # Check that last_token_issued_at was updated
        user.refresh_from_db()
        self.assertIsNotNone(user.last_token_issued_at)
        self.assertNotEqual(initial_token_time, user.last_token_issued_at)
        
        # Try logging in with new password
        self.client.credentials()  # Clear credentials
        new_login_data = {
            'email': 'verified@example.com',
            'password': 'newpassword456'
        }
        
        login_response = self.client.post(self.login_url, new_login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

    def test_change_password_with_incorrect_old_password(self):
        """Test changing password with incorrect old password"""
        # Login first to get token
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Try to change password with incorrect old password
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpassword456',
            'new_password2': 'newpassword456'
        }
        
        response = self.client.post(self.change_password_url, password_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_with_mismatched_new_passwords(self):
        """Test changing password with mismatched new passwords"""
        # Login first to get token
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Try to change password with mismatched new passwords
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_data = {
            'old_password': 'verifiedpass123',
            'new_password': 'newpassword456',
            'new_password2': 'differentpassword'
        }
        
        response = self.client.post(self.change_password_url, password_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_refresh(self):
        """Test refreshing access token"""
        # Login first to get tokens
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']
        
        # Get the initial token timestamp
        user = User.objects.get(email='verified@example.com')
        initial_token_time = user.last_token_issued_at
        
        # Refresh token
        refresh_data = {
            'refresh': refresh_token
        }
        
        response = self.client.post(self.token_refresh_url, refresh_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        
        # Check that last_token_issued_at was updated
        user.refresh_from_db()
        self.assertIsNotNone(user.last_token_issued_at)
        self.assertNotEqual(initial_token_time, user.last_token_issued_at)

    def test_token_refresh_with_invalid_token(self):
        """Test refreshing access token with invalid refresh token"""
        refresh_data = {
            'refresh': 'invalid.refresh.token'
        }
        
        response = self.client.post(self.token_refresh_url, refresh_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout(self):
        """Test user logout"""
        # Login first to get tokens
        login_data = {
            'email': 'verified@example.com',
            'password': 'verifiedpass123'
        }
        
        login_response = self.client.post(self.login_url, login_data, format='json')
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        
        # Logout
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        logout_data = {
            'refresh': refresh_token
        }
        
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logout successful')
        
        # Try to refresh token after logout (should fail)
        refresh_data = {
            'refresh': refresh_token
        }
        
        response = self.client.post(self.token_refresh_url, refresh_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unauthorized_access(self):
        """Test accessing protected endpoints without authentication"""
        # Try to access profile without token
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Try to change password without token
        password_data = {
            'old_password': 'verifiedpass123',
            'new_password': 'newpassword456',
            'new_password2': 'newpassword456'
        }
        
        response = self.client.post(self.change_password_url, password_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)