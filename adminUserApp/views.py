from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from licenseApplication.models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication
from .serializers import DynamicDashboardStatsSerializer

class DashboardStatsView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            new_apps_count = NewLicenseApplication.objects.count()
            reissue_apps_count = ReissueLicenseApplication.objects.count()
            renewal_apps_count = RenewalLicenseApplication.objects.count()
            total_completed = new_apps_count + reissue_apps_count + renewal_apps_count
            
            data = {
                'total_new_applications': new_apps_count,
                'total_reissues': reissue_apps_count,
                'total_renewals': renewal_apps_count,
                'total_completed': total_completed
            }
            
            serializer = DynamicDashboardStatsSerializer(data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
