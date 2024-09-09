from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from licenseApplication.models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication
from .serializers import DynamicDashboardStatsSerializer 
from .serializers import ApplicationSummarySerializer
from .permissions import IsAdminUserCustom
from rest_framework.permissions import IsAuthenticated



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
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

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
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

    def get(self, request, *args, **kwargs):
        try:
            # Querying the applicants manually
            new_apps = NewLicenseApplication.objects.all()
            reissue_apps = ReissueLicenseApplication.objects.all()
            renewal_apps = RenewalLicenseApplication.objects.all()

            # Adding a type_of_application field manually
            new_apps_data = ApplicationSummarySerializer(new_apps, many=True).data
            for app in new_apps_data:
                app['type_of_application'] = 'New Application'

            reissue_apps_data = ApplicationSummarySerializer(reissue_apps, many=True).data
            for app in reissue_apps_data:
                app['type_of_application'] = 'Reissue'

            renewal_apps_data = ApplicationSummarySerializer(renewal_apps, many=True).data
            for app in renewal_apps_data:
                app['type_of_application'] = 'Renewal'

            # Combining all applications into a single list
            all_applications = new_apps_data + reissue_apps_data + renewal_apps_data

            # Creating the final response data
            data = {
                "applications": all_applications
            }

            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            return custom_error_response(e)