from django.contrib import admin

from .models import ProtectedFile


@admin.register(ProtectedFile)
class ProtectedFileAdmin(admin.ModelAdmin):
    """Inspection only. Files are uploaded and managed in the DRM Hub."""
    list_display = ('title', 'category', 'status', 'uploaded_by', 'uploaded_at', 'expires_at')
    list_filter = ('category', 'status')
    search_fields = ('title', 'original_filename', 'sha256')
    exclude = ('storage_name',)
    readonly_fields = ('public_id', 'original_filename', 'extension', 'category', 'mime_type',
                       'size_bytes', 'sha256', 'uploaded_by', 'uploaded_at', 'updated_at')

    def has_add_permission(self, request):
        return False