from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'target', 'result', 'risk_score', 'user', 'created_at')
    list_filter = ('scan_type', 'result', 'created_at')
    search_fields = ('target', 'user__username', 'user__email')
