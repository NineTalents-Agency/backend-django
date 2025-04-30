from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
import random
import string
import logging

logger = logging.getLogger(__name__)

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        logger.info(f"User created with email: {email}")
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_token_issued_at = models.DateTimeField(null=True, blank=True)
    
    # Fields to track verification status
    email_verified = models.BooleanField(default=False)
    kyc_verified = models.BooleanField(default=False)
    
    # Additional user data
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)
        if is_new:
            logger.info(f"New user saved: {self.email}")
        else:
            logger.info(f"User updated: {self.email}")

class VerificationCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_codes')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    purpose = models.CharField(max_length=20, default='email_verification', 
                              choices=[
                                  ('email_verification', 'Email Verification'),
                                  ('password_reset', 'Password Reset'),
                                  ('two_factor', 'Two Factor Authentication')
                              ])
    
    @classmethod
    def generate_code(cls, user, purpose='email_verification'):
        """Generate a random 6-character alphanumeric code"""
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        # Set expiration time based on purpose
        if purpose == 'password_reset':
            # 15 minutes for password reset
            expires_at = timezone.now() + timezone.timedelta(minutes=15)
            logger.info(f"Password reset code generated for {user.email} (expires in 15 minutes)")
        else:
            # 15 minutes for email verification (changed from 24 hours)
            expires_at = timezone.now() + timezone.timedelta(minutes=30)
            logger.info(f"Verification code generated for {user.email} for purpose: {purpose} (expires in 30 minutes)")
        
        verification_code = cls.objects.create(
            user=user,
            code=code,
            expires_at=expires_at,
            purpose=purpose
        )
        
        return verification_code
    
    def is_valid(self):
        """Check if the code is valid (not used and not expired)"""
        return not self.is_used and self.expires_at > timezone.now()
    
    @classmethod
    def can_request_new_code(cls, user, purpose):
        """Check if user can request a new code (1 minute since last request)"""
        last_code = cls.objects.filter(
            user=user,
            purpose=purpose
        ).order_by('-created_at').first()
        
        if not last_code:
            return True
            
        time_elapsed = timezone.now() - last_code.created_at
        return time_elapsed.total_seconds() >= 60  # 1 minute cooldown
    
    @classmethod
    def get_cooldown_seconds(cls, user, purpose):
        """Get remaining cooldown seconds before user can request a new code"""
        last_code = cls.objects.filter(
            user=user,
            purpose=purpose
        ).order_by('-created_at').first()
        
        if not last_code:
            return 0
            
        time_elapsed = timezone.now() - last_code.created_at
        if time_elapsed.total_seconds() >= 60:
            return 0
        
        return int(60 - time_elapsed.total_seconds())
    
    def __str__(self):
        return f"{self.code} for {self.user.email} ({self.purpose})"