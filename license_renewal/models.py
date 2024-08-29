from django.db import models
from django.utils import timezone

class License(models.Model):
    email = models.EmailField(max_length=255, unique=True)
    license_id = models.CharField(max_length=20, unique=True)
    expiry_date = models.DateField()

    def is_active(self):
        return self.expiry_date > timezone.now()

    def __str__(self):
        return f"{self.license_id} - {self.email}"
