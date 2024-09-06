from django.urls import path
from .views import DashboardStatsView 
from .adminLogin_views import AdminUserLogin
from .adminProfile_views import AdminProfileUpdateView, AdminProfileView

urlpatterns = [
    path('api/admin/login/', AdminUserLogin.as_view(), name='admin-login'),
    path('dashboard-stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('api/admin/profile/', AdminProfileView.as_view(), name='admin-profile'),
    path('api/admin/profile/update/', AdminProfileUpdateView.as_view(), name='admin-profile-update'),
    
]