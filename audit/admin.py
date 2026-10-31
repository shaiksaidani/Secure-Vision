from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Read-only view for superusers. The in-app Activity Logs page comes in Phase 7."""
    list_display = ('timestamp', 'action', 'result', 'actor_label', 'target', 'ip_address')
    list_filter = ('action', 'result')
    search_fields = ('actor_label', 'target', 'ip_address')
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False