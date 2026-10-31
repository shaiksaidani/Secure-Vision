from django.contrib import admin

from .models import Device, DevicePolicy, User, UserSession


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """Inspection only. Users are created through Sign up (or createsuperuser)
    and managed in the in-app User Management page."""
    list_display = ('email', 'username', 'full_name', 'role', 'is_active', 'date_joined', 'last_login')
    list_filter = ('role', 'is_active')
    search_fields = ('email', 'username', 'full_name')
    exclude = ('password',)
    readonly_fields = ('last_login', 'date_joined')

    def has_add_permission(self, request):
        return False


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_label', 'ip_address', 'created_at', 'last_seen', 'ended_at', 'end_reason')
    exclude = ('session_key',)
    readonly_fields = ('user', 'device', 'ip_address', 'user_agent', 'created_at', 'last_seen', 'ended_at',
                       'end_reason')

    def has_add_permission(self, request):
        return False


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'kind', 'status', 'first_registered', 'last_active')
    list_filter = ('status', 'kind')
    exclude = ('token_hash',)
    readonly_fields = ('public_id', 'user', 'name', 'kind', 'user_agent', 'first_registered',
                       'last_active', 'last_ip', 'status', 'revoked_at', 'revoked_by')

    def has_add_permission(self, request):
        return False


@admin.register(DevicePolicy)
class DevicePolicyAdmin(admin.ModelAdmin):
    list_display = ('max_devices_per_user', 'updated_by', 'updated_at')
    readonly_fields = ('updated_by', 'updated_at')