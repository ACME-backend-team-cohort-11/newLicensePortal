from rest_framework import generics, status
from rest_framework.response import Response
from django.utils import timezone
from .models import License
from .serializers import LicenseSerializer


class LicenseDetailView(generics.RetrieveAPIView):
    queryset = License.objects.all()
    serializer_class = LicenseSerializer
    lookup_field = 'license_id'

    def get(self, request, *args, **kwargs):
        license_instance = self.get_object()
        if license_instance.is_active():
            return Response({
                'message': 'License is active',
                'license_details': self.get_serializer(license_instance).data
            })
        else:
            return Response({
                'message': 'License has expired',
                'license_details': self.get_serializer(license_instance).data
            }, status=status.HTTP_400_BAD_REQUEST)

class LicenseRenewalView(generics.UpdateAPIView):
    queryset = License.objects.all()
    serializer_class = LicenseSerializer
    lookup_field = 'license_id'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.is_active():
            return Response({
                'message': 'License is still active. No renewal needed.',
                'license_details': self.get_serializer(instance).data
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Renew license logic 
            instance.expiry_date = timezone.now().date().replace(year=timezone.now().year + 1)
            instance.save()
            return Response({
                'message': 'License renewed successfully',
                'license_details': self.get_serializer(instance).data
            })
