import random
import string

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


def generate_otp():
    """Generate a 6-digit numeric OTP."""
    return ''.join(random.choices(string.digits, k=6))


class ScanResult(models.Model):
    """Stores every URL and email scan for the dashboard."""

    SCAN_URL = 'url'
    SCAN_EMAIL = 'email'
    SCAN_TYPE_CHOICES = [
        (SCAN_URL, 'URL'),
        (SCAN_EMAIL, 'Email'),
    ]

    RESULT_PHISHING = 'phishing'
    RESULT_LEGITIMATE = 'legitimate'
    RESULT_SUSPICIOUS = 'suspicious'
    RESULT_CHOICES = [
        (RESULT_PHISHING, 'Phishing'),
        (RESULT_LEGITIMATE, 'Legitimate'),
        (RESULT_SUSPICIOUS, 'Suspicious'),
    ]

    FEEDBACK_CORRECT = 'correct'
    FEEDBACK_INCORRECT = 'incorrect'
    FEEDBACK_CHOICES = [
        (FEEDBACK_CORRECT, 'Correct'),
        (FEEDBACK_INCORRECT, 'Incorrect'),
    ]

    LABEL_CHOICES = [
        (RESULT_PHISHING, 'Phishing'),
        (RESULT_LEGITIMATE, 'Legitimate'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='scans')
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    target = models.TextField(help_text='The URL or sender email that was scanned')
    result = models.CharField(max_length=12, choices=RESULT_CHOICES)
    risk_score = models.FloatField(default=0, help_text='0-100 risk score')
    detection_source = models.CharField(max_length=50, blank=True, default='')
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    # User feedback fields — populated when users confirm or correct predictions
    user_feedback = models.CharField(max_length=10, choices=FEEDBACK_CHOICES, null=True, blank=True)
    feedback_label = models.CharField(max_length=12, choices=LABEL_CHOICES, null=True, blank=True,
                                      help_text='What the user says the correct label is')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.scan_type} | {self.target[:60]} | {self.result}'


class EmailVerificationToken(models.Model):
    """Stores a 6-digit OTP for email verification. Expires after EMAIL_VERIFICATION_EXPIRY_MINUTES."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification_token')
    token = models.CharField(max_length=6, default=generate_otp)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiry_minutes = getattr(settings, 'EMAIL_VERIFICATION_EXPIRY_MINUTES', 15)
        from datetime import timedelta
        return timezone.now() > self.created_at + timedelta(minutes=expiry_minutes)

    def __str__(self):
        return f'Verification OTP for {self.user.username}'


class PasswordResetToken(models.Model):
    """Stores a 6-digit OTP for password reset. Expires after PASSWORD_RESET_EXPIRY_MINUTES."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=6, default=generate_otp)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiry_minutes = getattr(settings, 'PASSWORD_RESET_EXPIRY_MINUTES', 10)
        from datetime import timedelta
        return timezone.now() > self.created_at + timedelta(minutes=expiry_minutes)

    def __str__(self):
        return f'Password reset OTP for {self.user.username}'
