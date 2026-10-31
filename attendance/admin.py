from django.contrib import admin

from .models import AttendanceRecord


@admin.register(AttendanceRecord)
class AttendanceRecordAdmin(admin.ModelAdmin):
    """Inspection only. Attendance is recorded through the Attendance pages."""
    list_display = ('user', 'date', 'status', 'check_in_at', 'check_out_at', 'check_in_device')
    list_filter = ('status', 'date')
    search_fields = ('user__email', 'user__full_name')
    readonly_fields = [f.name for f in AttendanceRecord._meta.fields]

    def has_add_permission(self, request):
        return False