from django.urls import path
from .views import LicenseDetailView, LicenseRenewalView

urlpatterns = [
    path('license/<str:license_id>/', LicenseDetailView.as_view(), name='license-detail'),
    path('license/<str:license_id>/renew/', LicenseRenewalView.as_view(), name='license-renew'),
]
