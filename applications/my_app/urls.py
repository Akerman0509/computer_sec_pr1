from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


app_name = "my_app"

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='login_page/login.html'), name='login'),

    # Auth APIs
    path('api/login/', views.api_login, name='login_api'),
    path('api/register/', views.api_register, name='register'),
    path('api/otp/verify/', views.api_otp_verify, name='otp_verify'),

    # User update
    path('user/update/', views.api_update_user, name='update_user'),

    # RSA key pair
    path('create_rsa_pair/', views.api_create_RSA_pair, name='create_rsa_pair'),

    # QR Code
    path('api/generate_qr/', views.generate_qr_code, name='generate_qr_code'),
    path('api/scan_qr/', views.read_qr_code, name='read_qr_code'),

]


