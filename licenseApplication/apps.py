from django.apps import AppConfig


class LicenseapplicationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'licenseApplication'
    
    # def ready(self):
    #     import licenseApplication.signals
