from django.contrib import admin

from .models import CustodyRecord, Evidence, Incident, IncidentEntry


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Incident)
class IncidentAdmin(ReadOnlyAdmin):
    list_display = ('reference', 'title', 'severity', 'status', 'assigned_to', 'created_at')
    list_filter = ('status', 'severity')


@admin.register(IncidentEntry)
class IncidentEntryAdmin(ReadOnlyAdmin):
    list_display = ('incident', 'kind', 'author', 'created_at')


@admin.register(Evidence)
class EvidenceAdmin(ReadOnlyAdmin):
    list_display = ('reference', 'title', 'kind', 'sha256', 'added_by', 'added_at')
    exclude = ('storage_name',)


@admin.register(CustodyRecord)
class CustodyRecordAdmin(ReadOnlyAdmin):
    list_display = ('evidence', 'action', 'actor_label', 'at')