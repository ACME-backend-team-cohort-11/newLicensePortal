from django.urls import path
from .views import replace_license
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    path('api/replace/', replace_license, name='replace_license'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
