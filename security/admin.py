from django.contrib import admin

from .models import SecurityAlert


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'user', 'occurrences', 'last_seen')
    list_filter = ('severity', 'status', 'kind')
    readonly_fields = [f.name for f in SecurityAlert._meta.fields]

    def has_add_permission(self, request):
        return False