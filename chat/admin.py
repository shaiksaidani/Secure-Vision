from django.contrib import admin

from .models import Conversation, Message


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    """Metadata only. Message text is deliberately not shown here."""
    list_display = ('public_id', 'kind', 'team', 'created_at', 'last_message_at')
    list_filter = ('kind',)
    readonly_fields = ('public_id', 'kind', 'team', 'direct_key', 'created_at', 'last_message_at')

    def has_add_permission(self, request):
        return False


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'conversation', 'sender', 'created_at', 'is_announcement', 'is_deleted')
    list_filter = ('is_deleted', 'is_announcement')
    exclude = ('body',)
    readonly_fields = ('conversation', 'sender', 'is_announcement', 'created_at', 'edited_at',
                       'is_deleted', 'deleted_at', 'deleted_by')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False