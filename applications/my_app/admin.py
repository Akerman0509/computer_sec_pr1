from django.contrib import admin



from .models import User, Key



@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'birth_day', 'phone_number', 'address', 'role')
    search_fields = ('email', 'name')
    list_filter = ('role',)
    
    
    