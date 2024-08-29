from django.db import models

class LicenseReplacement(models.Model):
    email = models.EmailField(max_length=255)
    license_id = models.CharField(max_length=20)
    affidavit_or_police_report = models.FileField(upload_to='affidavits_reports/')

    def __str__(self):
        return f'{self.license_id} - {self.email}'
