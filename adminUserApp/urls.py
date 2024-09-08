from django.urls import path
from .views import DashboardStatsView 
from .adminLogin_views import AdminUserLogin
from .adminProfile_views import AdminProfileUpdateView, AdminProfileView
from .views import AllApplicantsView
from .application_views.py import NewLicenseApplicationsView, ReissueLicenseApplicationsView,RenewalLicenseApplicationsView 


urlpatterns = [
    path('api/admin/login/', AdminUserLogin.as_view(), name='admin-login'),
    path('dashboard-stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('api/admin/profile/', AdminProfileView.as_view(), name='admin-profile'),
    path('api/admin/profile/update/', AdminProfileUpdateView.as_view(), name='admin-profile-update'),
    path('applicants/', AllApplicantsView.as_view(), name='all-applicants'),
    path('new-applications/', NewLicenseApplicationsView.as_view(), name='new-applications'),
    path('reissue-applications/', ReissueLicenseApplicationsView.as_view(), name='reissue-applications'),
    path('renewal-applications/', RenewalLicenseApplicationsView.as_view(), name='renewal-applications'),
]
