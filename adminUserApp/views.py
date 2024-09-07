from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from licenseApplication.models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication
from .serializers import DynamicDashboardStatsSerializer 
from .serializers import ApplicationSummarySerializer


# custom error handler
def custom_error_response(exception, error_code="INTERNAL_SERVER_ERROR", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR):
    return Response({
        "status": "error",
        "status_code": status_code,
        "error": {
            "code": error_code,
            "message": str(exception),
            "details": {}
        }
    }, status=status_code)

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
            return custom_error_response(e)

class AllApplicantsView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            # Querying the applicants manually
            new_apps = NewLicenseApplication.objects.all()
            reissue_apps = ReissueLicenseApplication.objects.all()
            renewal_apps = RenewalLicenseApplication.objects.all()
            
            # Serializing the data with only the required fields
            new_apps_serializer = ApplicationSummarySerializer(new_apps, many=True, model=NewLicenseApplication)
            reissue_apps_serializer = ApplicationSummarySerializer(reissue_apps, many=True, model=ReissueLicenseApplication)
            renewal_apps_serializer = ApplicationSummarySerializer(renewal_apps, many=True, model=RenewalLicenseApplication)

            data = {
                "new_applications": new_apps_serializer.data,
                "reissue_applications": reissue_apps_serializer.data,
                "renewal_applications": renewal_apps_serializer.data
            }
            
            return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return custom_error_response(e)
                