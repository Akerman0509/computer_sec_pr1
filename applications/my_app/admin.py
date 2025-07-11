from django.contrib import admin



from .models import User, Key, OTP



@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id','email', 'name', 'address', 'role', "account_status", 'created_at')
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
    
    
# @admin.register(OTP)
# class OTPAdmin(admin.ModelAdmin):
#     list_display = ('id', 'otp', 'otp_created', 'otp_expires', 'created_at')
#     search_fields = ('user__email',)
#     list_filter = ('otp_expires_at', 'created_at')
    
#     def user(self, obj):
#         return obj.user.email if obj.user else 'N/A'
    
#     user.short_description = 'User Email'
    
    
