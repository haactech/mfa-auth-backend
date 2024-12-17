from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views 

router = DefaultRouter()
router.register(r'trusted-devices', views.TrustedDeviceViewSet, basename='trusted-device')
router.register(r'security-alerts', views.SecurityAlertViewSet, basename='security-alert')

urlpatterns = [
    path('', include(router.urls)),
    path('login/', views.LoginView.as_view(), name='login'),
    path('verify-mfa/', views.VerifyMFAView.as_view(), name='verify-mfa'),
    path('setup-mfa/', views.SetupMFAView.as_view(), name='setup-mfa'),
    path('disable-mfa/', views.disable_mfa, name='disable-mfa'),
]