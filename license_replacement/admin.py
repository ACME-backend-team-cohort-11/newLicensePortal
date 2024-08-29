from django.contrib import admin
from .models import LicenseReplacement

@admin.register(LicenseReplacement)
class LicenseReplacementAdmin(admin.ModelAdmin):
    list_display = ('email', 'license_id', 'affidavit_or_police_report')
    search_fields = ('email', 'license_id')
