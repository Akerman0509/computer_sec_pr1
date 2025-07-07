from django.urls import path

from . import views
from django.contrib.auth import views as auth_views
from django.urls import path

app_name = "my_app"
urlpatterns = [
    # get

    # # Your login/logout views
    path('', auth_views.LoginView.as_view(template_name='login_page/login.html'), name='login'),

    
    path('login/', views.api_login, name='login_url'),
    path('register/', views.api_register, name='public_key_view'),
    
    # update user profile
    path('user/update/', views.api_update_user, name='update_user'),

    # create RSA key pair
    path ('create_rsa_pair/', views.api_create_RSA_pair, name='create_rsa_pair'),


]




