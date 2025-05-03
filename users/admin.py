from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, VerificationCode

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'custom_id', 'email', 'first_name', 'last_name', 'is_staff', 'email_verified', 'kyc_verified')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'email_verified', 'kyc_verified')
    fieldsets = (
        (None, {'fields': ('email', 'password', 'custom_id')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone_number', 'date_of_birth', 'address')}),
        (_('Verification'), {'fields': ('email_verified', 'kyc_verified')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    search_fields = ('email', 'first_name', 'last_name', 'custom_id')
    ordering = ('email',)
    readonly_fields = ('custom_id',)  # Make custom_id read-only in the admin

@admin.register(VerificationCode)
class VerificationCodeAdmin(admin.ModelAdmin):
    list_display = ('id', 'custom_id', 'code', 'user', 'purpose', 'created_at', 'expires_at', 'is_used')
    list_filter = ('is_used', 'purpose')
    search_fields = ('code', 'user__email', 'custom_id')
    ordering = ('-created_at',)
    readonly_fields = ('custom_id',)  # Make custom_id read-only in the admin