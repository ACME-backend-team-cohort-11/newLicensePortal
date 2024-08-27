from django.contrib import admin
from .models import LicenseRenewal

# Register your models here.

@admin.register(LicenseRenewal)
class LicenseRenewalAdmin(admin.ModelAdmin):
    list_display = ('email', 'license_id')
    search_fields = ('email', 'license_id')
