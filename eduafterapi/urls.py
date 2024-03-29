from django.urls import path, include
from rest_framework.routers import DefaultRouter
from django.conf.urls import include

from .views import SnippetViewSet, UserViewSet, SocialLoginView

# API endpoints
# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'snippets', SnippetViewSet)
router.register(r'users', UserViewSet)

# The API URLs are now determined automatically by the router.
urlpatterns = [
    path('', include(router.urls)),
    path('oauth/login/', SocialLoginView.as_view())
]

