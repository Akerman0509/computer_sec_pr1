from django.contrib import admin



from .models import User, Key



@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id','email', 'name', 'birth_day', 'phone_number', 'address', 'role')
    search_fields = ('email', 'name')
    list_filter = ('role',)
    
    
    
@admin.register(Key)
class KeyAdmin(admin.ModelAdmin):
    list_display = ('id','user__name', 'created_at', 'expires_at')
    search_fields = ('user__email',)
    list_filter = ('created_at', 'expires_at')
    
    def user(self, obj):
        return obj.user.email if obj.user else 'N/A'
    
    user.short_description = 'User Email'