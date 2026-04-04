from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *
from . import views

urlpatterns = [
    path('', Home.as_view(), name = 'home'),
    path('api/', Prediction.as_view(), name = 'prediction'),
    path('analyze_email/', views.analyze_email, name='analyze_email'),
    path('dashboard_stats/', views.dashboard_stats, name='dashboard_stats'),
    path('feedback/', views.submit_feedback, name='submit_feedback'),
    path('model_status/', views.model_status, name='model_status'),
    
    # Auth endpoints
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', UserProfileView.as_view(), name='user_profile'),
    
    # Email verification & password reset
    path('auth/verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('auth/resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),

    # Admin endpoints
    path('admin/users/', AdminUsersView.as_view(), name='admin_users'),
]