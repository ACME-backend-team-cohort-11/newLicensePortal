from django.db import models

# Create your models here.

class LicenseRenewal(models.Model):
    email = models.EmailField(max_length=255, unique=True)
    license_id = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return f'{self.license_id} - {self.email}'
