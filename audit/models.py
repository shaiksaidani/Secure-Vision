"""
Centralized, append-only audit log shared by every SecureVision module.

Every module records events through audit.services.log_event() so that the
Activity Logs, Security Center and Forensic Analyzer all read one timeline.
"""
import json
import uuid

from django.conf import settings
from django.db import models


class AuditLog(models.Model):

    class Action(models.TextChoices):
        # Phase 1 - identity
        SIGNUP = 'SIGNUP', 'Account created'
        LOGIN = 'LOGIN', 'Signed in'
        LOGOUT = 'LOGOUT', 'Signed out'
        FAILED_LOGIN = 'FAILED_LOGIN', 'Failed sign-in'
        PASSWORD_CHANGE = 'PASSWORD_CHANGE', 'Password changed'
        PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST', 'Password reset requested'
        PASSWORD_RESET = 'PASSWORD_RESET', 'Password reset completed'
        SESSION_REVOKED = 'SESSION_REVOKED', 'Session ended remotely'
        # Later phases (declared now so the vocabulary is stable)
        FILE_UPLOAD = 'FILE_UPLOAD', 'File uploaded'
        FILE_VIEW = 'FILE_VIEW', 'File viewed'
        FILE_DOWNLOAD = 'FILE_DOWNLOAD', 'File downloaded'
        FILE_EXPIRED = 'FILE_EXPIRED', 'File expired'
        INTEGRITY_FAILURE = 'INTEGRITY_FAILURE', 'File integrity check failed'
        ACCESS_DENIED = 'ACCESS_DENIED', 'Access denied'
        ACCESS_REQUEST = 'ACCESS_REQUEST', 'Access requested'
        ACCESS_APPROVED = 'ACCESS_APPROVED', 'Access approved'
        ACCESS_REJECTED = 'ACCESS_REJECTED', 'Access rejected'
        PERMISSION_CHANGED = 'PERMISSION_CHANGED', 'Role / permission changed'
        CHAT_MESSAGE = 'CHAT_MESSAGE', 'Chat message sent'
        MESSAGE_DELETE = 'MESSAGE_DELETE', 'Chat message deleted'
        ATTENDANCE_CHECK_IN = 'ATTENDANCE_CHECK_IN', 'Checked in'
        ATTENDANCE_CHECK_OUT = 'ATTENDANCE_CHECK_OUT', 'Checked out'
        ATTENDANCE_MARKED = 'ATTENDANCE_MARKED', 'Attendance marked by admin'
        ATTENDANCE_EXPORTED = 'ATTENDANCE_EXPORTED', 'Attendance report exported'
        DEVICE_REGISTERED = 'DEVICE_REGISTERED', 'Device registered'
        DEVICE_REVOKED = 'DEVICE_REVOKED', 'Device revoked'
        DEVICE_BLOCKED = 'DEVICE_BLOCKED', 'Sign-in blocked by device policy'
        DEVICE_POLICY_CHANGED = 'DEVICE_POLICY_CHANGED', 'Device policy changed'
        TEAM_CREATED = 'TEAM_CREATED', 'Team created'
        TEAM_UPDATED = 'TEAM_UPDATED', 'Team updated'
        TEAM_MEMBER_ADDED = 'TEAM_MEMBER_ADDED', 'Member added to team'
        TEAM_MEMBER_REMOVED = 'TEAM_MEMBER_REMOVED', 'Member removed from team'
        USER_ADDED = 'USER_ADDED', 'User added'
        USER_REMOVED = 'USER_REMOVED', 'User deactivated'
        USER_REACTIVATED = 'USER_REACTIVATED', 'User reactivated'
        FORENSIC_ANALYSIS = 'FORENSIC_ANALYSIS', 'Forensic analysis run'
        ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account temporarily locked'
        ALERT_UPDATED = 'ALERT_UPDATED', 'Security alert updated'
        AUDIT_EXPORTED = 'AUDIT_EXPORTED', 'Activity log exported'
        INCIDENT_CREATED = 'INCIDENT_CREATED', 'Incident opened'
        INCIDENT_UPDATED = 'INCIDENT_UPDATED', 'Incident updated'
        EVIDENCE_ADDED = 'EVIDENCE_ADDED', 'Evidence added'
        EVIDENCE_ACCESSED = 'EVIDENCE_ACCESSED', 'Evidence downloaded'
        EVIDENCE_VERIFIED = 'EVIDENCE_VERIFIED', 'Evidence integrity checked'
        REPORT_GENERATED = 'REPORT_GENERATED', 'Report generated'

    class Result(models.TextChoices):
        SUCCESS = 'SUCCESS', 'Success'
        FAILURE = 'FAILURE', 'Failure'
        DENIED = 'DENIED', 'Denied'
        INFO = 'INFO', 'Info'

    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    # The real database user. SET_NULL keeps history if a user is ever deleted.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='audit_events')
    # Snapshot of who acted (e.g. the email typed in a failed sign-in).
    actor_label = models.CharField(max_length=254, blank=True)
    action = models.CharField(max_length=40, choices=Action.choices, db_index=True)
    target = models.CharField(max_length=255, blank=True)
    result = models.CharField(max_length=10, choices=Result.choices, default=Result.SUCCESS)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    # A one-way fingerprint of the session, never the raw session key, so the
    # log can correlate events without exposing a usable credential.
    session_ref = models.CharField(max_length=16, blank=True)
    details = models.TextField(blank=True)  # JSON text

    class Meta:
        ordering = ('-timestamp', '-id')
        indexes = [models.Index(fields=['user', 'timestamp'])]

    def __str__(self):
        return '{} {} {}'.format(self.timestamp, self.action, self.actor_label)

    # Append-only: entries can be created, never edited or deleted via the ORM.
    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError('Audit log entries are append-only.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError('Audit log entries cannot be deleted.')

    @property
    def details_dict(self):
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except ValueError:
            return {}