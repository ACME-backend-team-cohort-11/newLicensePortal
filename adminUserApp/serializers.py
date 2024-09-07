from rest_framework import serializers
from userAuth.models import CustomUser
from .models import AdminProfile


class AdminProfileViewSerializer(serializers.ModelSerializer):
    """
    Serializer to view both user and profile data
    """
    class Meta:
        model = AdminProfile
        fields = ['date_of_birth', 'present_address', 'permanent_address', 'city', 'postal_code', 'country', 'profile_picture']

class AdminProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating profile (excluding full_name, email, and password)
    """
    class Meta:
        model = AdminProfile
        fields = ['date_of_birth', 'present_address', 'permanent_address', 'city', 'postal_code', 'country', 'profile_picture']

class AdminUserSerializer(serializers.ModelSerializer):
    """
    Serializer for viewing admin user details
    """
    profile = AdminProfileViewSerializer(source='adminprofile')

    class Meta:
        model = CustomUser
        fields = ['full_name', 'username', 'email', 'profile']


class DynamicDashboardStatsSerializer(serializers.Serializer):
    total_new_applications = serializers.IntegerField()
    total_reissues = serializers.IntegerField()
    total_renewals = serializers.IntegerField()
    total_completed = serializers.IntegerField()
