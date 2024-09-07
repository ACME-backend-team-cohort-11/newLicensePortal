from rest_framework import serializers
from userAuth.models import CustomUser
from .models import AdminProfile
from licenseApplication.models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication


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

class ApplicationSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = None  # No specific model because it will be overriden
        fields = ['id', 'name', 'address', 'date', 'type_of_application', 'status']  # Customizing fields to return what we expect

    def __init__(self, *args, **kwargs):
        # Overriding the model dynamically based on the type of application
        model = kwargs.pop('model', None)
        super(ApplicationSummarySerializer, self).__init__(*args, **kwargs)
        if model is not None:
            self.Meta.model = model