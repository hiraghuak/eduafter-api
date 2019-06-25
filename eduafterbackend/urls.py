from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('eduafterapi.urls')),
    path('api/auth/oauth/', include('rest_framework_social_oauth2.urls')),
]
