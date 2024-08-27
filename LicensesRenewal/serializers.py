from rest_framework import serializers
from .models import LicenseRenewal

class LicenseRenewalSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseRenewal
        fields = ['email', 'license_id']
