from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view, permission_classes
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    VerifyEmailSerializer, ResendVerificationSerializer,
    UpdateUserSerializer, PasswordChangeSerializer,
    ForgotPasswordSerializer, ResetPasswordSerializer
)
from users.models import VerificationCode
from .utils import send_verification_email, send_password_reset_email
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
        
        # Generate verification code with 15-minute expiration
        verification_code = VerificationCode.generate_code(user, purpose='email_verification')
        
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
            "message": "Verification code has been sent to your email. It will expire in 30 minutes." if email_sent else "Account created but verification email could not be sent. Please request a new code."
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
            verification_code = VerificationCode.generate_code(user, purpose='email_verification')
            send_verification_email(user, verification_code.code)

            return Response(
                {"error": "Email not verified. A verification code has been sent to your email. It will expire in 30 minutes."},
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
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh")
            
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Blacklist the token
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Log the successful logout
            logger.info(f"User {request.user.email} logged out successfully")
            
            return Response(
                {"message": "Logout successful"},
                status=status.HTTP_200_OK
            )
            
        except TokenError as e:
            logger.warning(f"Invalid token during logout for user {request.user.email}: {str(e)}")
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            logger.error(f"Logout error for user {request.user.email}: {str(e)}")
            return Response(
                {"error": "An error occurred during logout"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        
# class LogoutView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request):
#         try:
#             refresh_token = request.data["refresh"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()
#             return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
#         except Exception as e:
#             logger.error(f"Logout error: {str(e)}")
#             return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        
   #logout from all device     
class LogoutAllView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        try:
            # Get all valid tokens for the user and blacklist them
            user = request.user
            
            # Update last_token_issued_at to invalidate all previous tokens
            user.last_token_issued_at = timezone.now()
            user.save(update_fields=['last_token_issued_at'])
            
            # Log the action
            logger.info(f"User {user.email} logged out from all devices")
            
            return Response(
                {"message": "Successfully logged out from all devices"},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Error during logout-all for user {request.user.email}: {str(e)}")
            return Response(
                {"error": "An error occurred during logout from all devices"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )       

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

            # Check if user is already verified
            if user.email_verified:
                return Response(
                    {"message": "Your email is already verified."},
                    status=status.HTTP_200_OK
                )

            # Check if enough time has passed to resend the code (1 minute)
            if not VerificationCode.can_request_new_code(user, 'email_verification'):
                cooldown_seconds = VerificationCode.get_cooldown_seconds(user, 'email_verification')
                return Response(
                    {"error": f"Please wait {cooldown_seconds} seconds before requesting a new code."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            # Generate new verification code with 15-minute expiration
            verification_code = VerificationCode.generate_code(user, purpose='email_verification')

            # Send verification email
            email_sent = send_verification_email(user, verification_code.code)

            if email_sent:
                message = "Verification code has been sent to your email. It will expire in 30 minutes."
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


class ForgotPasswordView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Check if enough time has passed to request a new code (1 minute)
            if not VerificationCode.can_request_new_code(user, 'password_reset'):
                cooldown_seconds = VerificationCode.get_cooldown_seconds(user, 'password_reset')
                return Response(
                    {"error": f"Please wait {cooldown_seconds} seconds before requesting a new code."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Generate password reset code with 15-minute expiration
            reset_code = VerificationCode.generate_code(user, purpose='password_reset')
            
            # Send password reset email
            email_sent = send_password_reset_email(user, reset_code.code)
            
            # For security reasons, always return success even if email fails
            # But log the failure
            if not email_sent:
                logger.error(f"Failed to send password reset email to {email}")
            
            return Response({
                "message": "If your email is registered, you will receive a password reset code. It will expire in 15 minutes."
            })
            
        except User.DoesNotExist:
            # For security reasons, don't reveal that the user doesn't exist
            logger.info(f"Password reset attempted for non-existent email: {email}")
            return Response({
                "message": "If your email is registered, you will receive a password reset code. It will expire in 15 minutes."
            })

class ResetPasswordView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        new_password = serializer.validated_data['new_password']
        
        try:
            user = User.objects.get(email=email)
            verification_code = VerificationCode.objects.filter(
                user=user,
                code=code,
                is_used=False,
                purpose='password_reset',
                expires_at__gt=timezone.now()
            ).order_by('-created_at').first()
            
            if not verification_code:
                logger.warning(f"Invalid or expired password reset code attempt for {email}")
                return Response(
                    {"error": "Invalid or expired password reset code."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Mark code as used
            verification_code.is_used = True
            verification_code.save()
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            logger.info(f"Password reset successfully for {email}")
            
            return Response({
                "message": "Password has been reset successfully. You can now log in with your new password."
            })
            
        except User.DoesNotExist:
            logger.warning(f"Password reset attempt for non-existent user: {email}")
            return Response(
                {"error": "Invalid email or code."},
                status=status.HTTP_400_BAD_REQUEST
            )
