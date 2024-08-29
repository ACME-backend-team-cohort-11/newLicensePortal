from django.contrib import admin
from .models import License

@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = ('email', 'license_id', 'expiry_date', 'is_active')
    search_fields = ('email', 'license_id')
    list_filter = ('expiry_date',)
    ordering = ('-expiry_date',)

    def is_active(self, obj):
        return obj.is_active()
    is_active.boolean = True
    is_active.short_description = 'Active'

# admin.site.register(License, LicenseAdmin)
