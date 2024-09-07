from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.http import Http404

from .utils import format_error_response, logger


from .models import Profile
from .permissions import IsRegularUser
from .serializers import ProfileSerializer


class ProfileDetail(RetrieveAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsRegularUser]

    def get_queryset(self):
        return Profile.objects.filter(user=self.request.user)

    def get_object(self):
        queryset = self.get_queryset()
        pk = self.kwargs.get('pk')
        return get_object_or_404(queryset, pk=pk)

    def get(self, request, *args, **kwargs):
        try:
            profile = self.get_object()
            serializer = self.get_serializer(profile)
            logger.info(f"Profile retrieved for user: {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Http404:
            logger.warning(f"Profile not found for user {request.user.email} with pk={self.kwargs.get('pk')}")
            return Response(format_error_response(
                status_code=status.HTTP_404_NOT_FOUND,
                error_code="PROFILE_NOT_FOUND",
                message="Profile not found.",
                details={"pk": self.kwargs.get('pk')}
            ), status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error(f"Error retrieving profile for user {request.user.email}: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="PROFILE_RETRIEVAL_ERROR",
                message="An error occurred while retrieving the profile.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
