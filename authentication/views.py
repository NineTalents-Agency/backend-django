from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    VerifyEmailSerializer, ResendVerificationSerializer,
    UpdateUserSerializer, PasswordChangeSerializer
)
from users.models import VerificationCode
from .utils import send_verification_email
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate verification code
        verification_code = VerificationCode.generate_code(user)
        
        # Send verification email
        email_sent = send_verification_email(user, verification_code.code)
        
        if not email_sent:
            logger.warning(f"Failed to send verification email during registration for {user.email}")
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
          # Update last_token_issued_at
        user.last_token_issued_at = timezone.now()
        user.save(update_fields=['last_token_issued_at'])
        
        return Response({
            "user": UserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "message": "Verification code has been sent to your email." if email_sent else "Account created but verification email could not be sent. Please request a new code."
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        # Deserialize and validate data
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Retrieve the user instance from the validated data
        user = serializer.validated_data.get('user')  # This assumes 'user' is part of validated_data from the serializer
        password = serializer.validated_data.get("password")

        # Check if the user exists
        if user is None:
            raise AuthenticationFailed("Invalid email or password.")

        # Check if the password matches the user
        if not user.check_password(password):
            raise AuthenticationFailed("Invalid email or password.")

        # Rate limit logic (one token every 30 seconds)
        cooldown = timedelta(seconds=30)
        now = timezone.now()
        if user.last_token_issued_at and (now - user.last_token_issued_at) < cooldown:
            remaining = cooldown - (now - user.last_token_issued_at)
            return Response(
                {"error": f"Too many token requests. Try again in {remaining.seconds} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Issue tokens after rate limit is passed
        refresh = RefreshToken.for_user(user)
        user.last_token_issued_at = now
        user.save(update_fields=['last_token_issued_at'])

        # Check if email is verified
        if not user.email_verified:
            verification_code = VerificationCode.generate_code(user)
            send_verification_email(user, verification_code.code)

            return Response(
                {"error": "Email not verified. A verification code has been sent to your email."},
                status=status.HTTP_403_FORBIDDEN
            )

        return Response({
            "user": UserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "message": "Login successful.",
            "email_verified": user.email_verified
        })


        
class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = UpdateUserSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response(UserSerializer(instance).data)

class VerifyEmailView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        
        try:
            user = User.objects.get(email=email)
            verification_code = VerificationCode.objects.filter(
                user=user,
                code=code,
                is_used=False,
                purpose='email_verification',
                expires_at__gt=timezone.now()
            ).order_by('-created_at').first()
            
            if not verification_code:
                logger.warning(f"Invalid or expired verification code attempt for {email}")
                return Response(
                    {"error": "Invalid or expired verification code."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Mark code as used
            verification_code.is_used = True
            verification_code.save()
            
            # Mark user as verified
            user.email_verified = True
            user.is_active = True
            user.save()
            
            logger.info(f"Email verified successfully for {email}")
            
             
            # Generate tokens for automatic login
            refresh = RefreshToken.for_user(user)
            
             # Update last_token_issued_at
            user.last_token_issued_at = timezone.now()
            user.save(update_fields=['last_token_issued_at'])
                
            
            return Response({
                "message": "Email verified successfully.",
                "user": UserSerializer(user).data,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            })
            
        except User.DoesNotExist:
            logger.warning(f"Verification attempt for non-existent user: {email}")
            return Response(
                {"error": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

            

class ResendVerificationView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)

            # Check if enough time has passed to resend the code (10 minutes)
            try:
                verification_code = VerificationCode.objects.get(user=user)
                time_elapsed = timezone.now() - verification_code.created_at

                if time_elapsed < timedelta(minutes=10):
                    remaining_time = timedelta(minutes=10) - time_elapsed
                    return Response(
                        {"error": f"Too soon to resend the verification code. Try again in {remaining_time.seconds // 60} minutes."},
                        status=status.HTTP_429_TOO_MANY_REQUESTS
                    )
                else:
                    verification_code.delete()  # Delete old code before creating a new one
            except VerificationCode.DoesNotExist:
                pass  # If no code exists, create a new one

            # Generate new verification code
            verification_code = VerificationCode.generate_code(user)

            # Send verification email
            email_sent = send_verification_email(user, verification_code.code)

            if email_sent:
                message = "Verification code has been sent to your email."
                if user.email_verified:
                    message = "Your email is already verified, but a new code has been sent."
            else:
                message = "Failed to send verification code. Please try again later."
                logger.error(f"Failed to send verification email to {email}")

            return Response({"message": message})

        except User.DoesNotExist:
            logger.warning(f"Resend verification attempt for non-existent user: {email}")
            return Response(
                {"error": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )            




class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # Check if old password is correct
        if not user.check_password(old_password):
            return Response(
                {"error": "Current password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        logger.info(f"Password changed for user: {user.email}")
        
        # Generate new tokens
        refresh = RefreshToken.for_user(user)
        
         # Update last_token_issued_at
        user.last_token_issued_at = timezone.now()
        user.save(update_fields=['last_token_issued_at'])
                
        
        return Response({
            "message": "Password changed successfully.",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        })

class KYCStatusUpdateView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.kyc_verified = request.data.get('kyc_verified', False)
            user.save()
            logger.info(f"KYC status updated for user {user.email}: {user.kyc_verified}")
            return Response({"message": "KYC status updated successfully."})
        except User.DoesNotExist:
            logger.warning(f"KYC status update attempt for non-existent user ID: {user_id}")
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

class HealthCheckView(APIView):
    permission_classes = (AllowAny,)
    
    def get(self, request):
        return Response({"status": "healthy"})