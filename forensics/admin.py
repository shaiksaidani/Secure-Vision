from django.contrib import admin

from .models import ForensicAnalysis, Watermark


@admin.register(Watermark)
class WatermarkAdmin(admin.ModelAdmin):
    list_display = ('code', 'file', 'recipient', 'purpose', 'issued_on', 'times_served')
    list_filter = ('purpose',)
    search_fields = ('code', 'recipient__email', 'file__title')
    readonly_fields = [f.name for f in Watermark._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(ForensicAnalysis)
class ForensicAnalysisAdmin(admin.ModelAdmin):
    list_display = ('sample_name', 'risk', 'tampered', 'watermark_status', 'analyst', 'created_at')
    list_filter = ('risk', 'tampered', 'watermark_status')
    exclude = ('sample_storage',)
    readonly_fields = [f.name for f in ForensicAnalysis._meta.fields if f.name != 'sample_storage']

    def has_add_permission(self, request):
        return False