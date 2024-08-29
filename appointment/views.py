from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import ScheduleAppointmentSerializer

class ScheduleAppointmentView(APIView):
    def post(self, request):
        serializer = ScheduleAppointmentSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            appointment = serializer.save(user=request.user)
            return Response({
                "status": "success",
                "status_code": 201,
                "data": {"appointment_id": appointment.id}
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

