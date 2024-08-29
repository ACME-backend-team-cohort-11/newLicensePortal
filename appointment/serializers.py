from rest_framework import serializers
from .models import ScheduleAppointment

class ScheduleAppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduleAppointment
        fields = ['full_name', 'phone_number', 'message', 'email_address', 'available_date', 'application_type']

    def validate_application_type(self, value):
        if value not in ['new application', 'reissue', 'renewal']:
            raise serializers.ValidationError({
                "status": "error",
                "status_code": 400,
                "error": {
                    "code": "INVALID_APPLICATION_TYPE",
                    "message": "Invalid application type. Must be 'new application', 'reissue', or 'renewal'.",
                    "details": {}
                }
            })
        return value
