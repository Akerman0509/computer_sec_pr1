from django.urls import path, re_path
from . import views
from django.contrib.auth import views as auth_views


app_name = "my_app"

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='login_page/login.html'), name='login'),

    
    path('login/', views.api_login, name='login_url'),
    path('register/', views.api_register, name='public_key_view'),
    path('otp/verify/', views.api_otp_verify, name='otp_verify'),    
    # update user profile
    path('user/update/', views.api_update_user, name='update_user'),

    # RSA key pair
    path('create_rsa_pair/', views.api_create_RSA_pair, name='create_rsa_pair'),

    path ('send_encrypted_file/', views.api_send_encrypted_file, name='send_encrypted_file'),
    path ('decrypt_file/', views.api_decrypt_file, name='send_encrypted_file'),
    
    # QR Code
    path('api/generate_qr/', views.generate_qr_code, name='generate_qr_code'),
    path('api/scan_qr/', views.read_qr_code, name='read_qr_code'),
    
    
    # search
    re_path(r'^public_key_by_email/(?P<email>[^/]+)/$', views.api_public_key_by_email, name='public_key_by_email'),
    
    
    
    
    
    path('serve_jpg/', views.serve_jpg, name='serve_jpg'),

    

]


