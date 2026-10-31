from django.contrib import admin

from .models import Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'kind', 'title', 'created_at', 'read_at')
    list_filter = ('kind',)
    search_fields = ('user__email', 'title')
    readonly_fields = [f.name for f in Notification._meta.fields]

    def has_add_permission(self, request):
        return False