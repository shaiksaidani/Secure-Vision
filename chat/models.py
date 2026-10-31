"""Confidential one-to-one chat and team community chat.

Every participant is a real accounts.User; nothing about who is talking is
kept in the browser. Messages are never physically deleted by users: deletion
is a recorded, soft delete.
"""
import uuid

from django.conf import settings
from django.db import models


class Conversation(models.Model):

    class Kind(models.TextChoices):
        DIRECT = 'DIRECT', 'Direct message'
        TEAM = 'TEAM', 'Team community'

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    # TEAM conversations: exactly one per team. Access follows team membership.
    team = models.OneToOneField('teams.Team', null=True, blank=True, on_delete=models.CASCADE,
                                related_name='community')
    # DIRECT conversations: "<smaller user id>:<larger user id>", so a pair of
    # people always shares one conversation.
    direct_key = models.CharField(max_length=64, null=True, blank=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_message_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ('-last_message_at', '-created_at')

    def __str__(self):
        if self.kind == self.Kind.TEAM and self.team_id:
            return 'Team: {}'.format(self.team.name)
        return 'Direct {}'.format(self.direct_key)

    @staticmethod
    def key_for(user_a, user_b):
        low, high = sorted([user_a.pk, user_b.pk])
        return '{}:{}'.format(low, high)


class ConversationMember(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='chat_memberships')
    joined_at = models.DateTimeField(auto_now_add=True)
    last_read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['conversation', 'user'], name='unique_conversation_member'),
        ]


class Message(models.Model):
    MAX_LENGTH = 4000

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                               related_name='chat_messages')
    body = models.TextField(max_length=MAX_LENGTH)
    is_announcement = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    edited_at = models.DateTimeField(null=True, blank=True)
    # Soft delete: the row stays for the audit trail; the text is never shown again.
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name='+')

    class Meta:
        ordering = ('created_at', 'id')

    def __str__(self):
        return 'Message {} in {}'.format(self.pk, self.conversation_id)