from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication
from .serializers import NewLicenseApplicationSerializer, ReissueLicenseApplicationSerializer, RenewalLicenseApplicationSerializer
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

class NewLicenseApplicationsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

    def get(self, request, *args, **kwargs):
        try:
            # Querying new license applications
            new_apps = NewLicenseApplication.objects.all()
            
            # Serializing the data with specific fields
            serializer = NewLicenseApplicationSerializer(new_apps, many=True)

            data = {
                "new_applications": serializer.data
            }
            
            return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return custom_error_response(e)

class ReissueLicenseApplicationsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access
    def get(self, request, *args, **kwargs):
        try:
            # Querying reissue license applications
            reissue_apps = ReissueLicenseApplication.objects.all()
            
            # Serializing the data with specific fields
            serializer = ReissueLicenseApplicationSerializer(reissue_apps, many=True)

            data = {
                "reissue_applications": serializer.data
            }
            
            return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return custom_error_response(e)
        

class RenewalLicenseApplicationsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

    def get(self, request, *args, **kwargs):
        try:
            # Querying renewal license applications
            renewal_apps = RenewalLicenseApplication.objects.all()
            
            # Serializing the data with specific fields
            serializer = RenewalLicenseApplicationSerializer(renewal_apps, many=True)

            data = {
                "renewal_applications": serializer.data
            }
            
            return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return custom_error_response(e)
