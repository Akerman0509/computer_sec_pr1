from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


app_name = "my_app"

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='login_page/login.html'), name='login'),
    path('api/login/', views.api_login, name='user_login'),
    path('api/register/', views.api_register, name='user_register'),
    path('api/otp/verify/', views.api_otp_verify, name='otp_verify'),

]
