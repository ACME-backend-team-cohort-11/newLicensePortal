from rest_framework import serializers
from .models import LicenseReplacement

class LicenseReplacementSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseReplacement
        fields = ['email', 'license_id', 'affidavit_or_police_report']
