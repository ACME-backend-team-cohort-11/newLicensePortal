from rest_framework import serializers

class DynamicDashboardStatsSerializer(serializers.Serializer):
    total_new_applications = serializers.IntegerField()
    total_reissues = serializers.IntegerField()
    total_renewals = serializers.IntegerField()
    total_completed = serializers.IntegerField()
