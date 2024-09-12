from rest_framework import serializers
from .models import NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit

class NewLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewLicenseApplication
        fields = [
            'id', 'user', 'application_type','vehicle_type', 'validity_year' ,'status', 
            'first_name', 'last_name', 'middle_name', 
            'gender', 'date_of_birth', 'mother_maiden_name', 
            'NIN', 'passport_photo', 'phone_number', 'email', 
            'street_address', 'local_government_of_residence', 'state_of_residence',
            'height', 'blood_group', 'local_government_of_origin', 'state_of_origin',
            'nationality', 'facial_mark', 'require_glasses', 
            'next_of_kin_full_name', 'next_of_kin_phone_number',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']


class RenewalLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RenewalLicenseApplication
        fields = ['id', 'user', 'application_type', 'vehicle_type', 'validity_year', 'status', 'email', 'license_id',
                  'created_at', 'updated_at']
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']

class ReissueLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReissueLicenseApplication
        fields = ['id', 'user', 'application_type', 'vehicle_type', 'validity_year','status', 'email', 'license_id',
                  'affidavit', 'police_report', 'created_at', 'updated_at']
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']

class ApplicationAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicationAudit
        fields = ['id', 'application', 'old_status', 'new_status', 'changed_by', 'timestamp', 'notes']
        read_only_fields = ['application', 'old_status', 'new_status', 'changed_by', 'timestamp']
