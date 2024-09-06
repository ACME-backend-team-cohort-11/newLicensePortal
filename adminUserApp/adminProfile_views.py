from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import AdminUserSerializer, AdminProfileUpdateSerializer
from .permissions import IsAdminUserCustom  # Custom permission
from userAuth.utils import format_error_response


class AdminProfileView(generics.RetrieveAPIView):
    """
    View for admins to see their complete profile details
    """
    serializer_class = AdminUserSerializer
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

    @swagger_auto_schema(
        operation_description="Retrieve the authenticated user's profile details.",
        responses={
            200: openapi.Response("Profile retrieves successfully"),
            400: openapi.Response("Forbidden Access")
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            return self.retrieve(request, *args, **kwargs)
        except Exception as e :
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="PROFILE_RETRIEVE_ERROR",
                message="An error occured while retrieving the profile",
                details= {"exception": str(e)}
            ), status.HTTP_500_INTERNAL_SERVER_ERROR) 
    
    def get_object(self):
        return self.request.user


class AdminProfileUpdateView(generics.UpdateAPIView):
    """
    View for admins to update their profile details (excluding full_name, email, and password)
    """
    serializer_class = AdminProfileUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminUserCustom]  # Only authenticated admins can access

    @swagger_auto_schema(
        operation_description="Update the authenticated admin user's profile details.",
        responses={
            200: openapi.Response("Profile updated successfully."),
            400: openapi.Response("Validation error or incomplete data."),
            403: openapi.Response("Forbidden access."),
            500: openapi.Response("Error occurred while updating the profile."),
        }
    )
    def put(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
                message="Invalid or incomplete data provided.",
                details=serializer.errors
            ), status=status.HTTP_400_BAD_REQUEST)

        try:
            return self.partial_update(request, *args, **kwargs)
        except Exception as e:
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="PROFILE_UPDATE_ERROR",
                message="An error occurred while updating the profile.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_object(self):
        return self.request.user.adminprofile
        


