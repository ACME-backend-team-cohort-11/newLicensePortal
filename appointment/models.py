from django.db import models
from django.db import models
from userAuth.models import CustomUser

class ScheduleAppointment(models.Model):
    APPLICATION_TYPE_CHOICES = [
        ('new application', 'New Application'),
        ('reissue', 'Reissue'),
        ('renewal', 'Renewal'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='appointments')
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    message = models.TextField(blank=True, null=True)
    email_address = models.EmailField()
    available_date = models.DateField()
    application_type = models.CharField(max_length=20, choices=APPLICATION_TYPE_CHOICES)

    def __str__(self):
        return f"{self.full_name} - {self.available_date} - {self.application_type}"

