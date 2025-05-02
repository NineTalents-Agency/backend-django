from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView, LoginView, LogoutView, UserProfileView,
    VerifyEmailView, ResendVerificationView, KYCStatusUpdateView,
    HealthCheckView, PasswordChangeView, ForgotPasswordView, ResetPasswordView, LogoutAllView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout-all/', LogoutAllView.as_view(), name='logout_all'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('change-password/', PasswordChangeView.as_view(), name='change_password'),
    path('users/<int:user_id>/kyc-status/', KYCStatusUpdateView.as_view(), name='kyc_status_update'),
    path('health/', HealthCheckView.as_view(), name='health'),
    
    # New forgotten password URLs
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
]