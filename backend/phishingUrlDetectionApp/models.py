from django.db import models
from django.utils import timezone


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

    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    target = models.TextField(help_text='The URL or sender email that was scanned')
    result = models.CharField(max_length=12, choices=RESULT_CHOICES)
    risk_score = models.FloatField(default=0, help_text='0-100 risk score')
    detection_source = models.CharField(max_length=50, blank=True, default='')
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.scan_type} | {self.target[:60]} | {self.result}'
