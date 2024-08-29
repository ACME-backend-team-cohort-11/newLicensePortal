from rest_framework import serializers
from .models import License

class LicenseSerializer(serializers.ModelSerializer):
    is_active = serializers.SerializerMethodField()

    class Meta:
        model = License
        fields = ['email', 'license_id', 'expiry_date', 'is_active']

    def get_is_active(self, obj):
        return obj.is_active()
