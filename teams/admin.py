from django.contrib import admin

from .models import Team, TeamMembership


class TeamMembershipInline(admin.TabularInline):
    model = TeamMembership
    fk_name = 'team'
    extra = 0
    readonly_fields = ('user', 'added_by', 'joined_at')
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    """Inspection only. Teams are managed in the in-app Teams page."""
    list_display = ('name', 'leader', 'created_by', 'created_at')
    search_fields = ('name',)
    readonly_fields = ('created_by', 'created_at', 'updated_at')
    inlines = [TeamMembershipInline]