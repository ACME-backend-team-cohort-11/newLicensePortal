from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import LicenseReplacement
from .serializers import LicenseReplacementSerializer

@api_view(['POST'])
def replace_license(request):
    if request.method == 'POST':
        serializer = LicenseReplacementSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
