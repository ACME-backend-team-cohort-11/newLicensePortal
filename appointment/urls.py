from django.urls import path
from .views import ScheduleAppointmentView

urlpatterns = [
    path('schedule/', ScheduleAppointmentView.as_view(), name='schedule-appointment'),
]
