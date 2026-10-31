"""Security alerts raised automatically from the audit log."""
import uuid

from django.conf import settings
from django.db import models


class SecurityAlert(models.Model):

    class Kind(models.TextChoices):
        REPEATED_DENIALS = 'REPEATED_DENIALS', 'Multiple denied access attempts'
        ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account locked after failed sign-ins'
        SIGNIN_SPRAY = 'SIGNIN_SPRAY', 'Many failed sign-ins from one address'
        DEVICE_BLOCKED = 'DEVICE_BLOCKED', 'Sign-in blocked by device policy'
        INTEGRITY_FAILURE = 'INTEGRITY_FAILURE', 'Protected file failed integrity check'
        TRACED_LEAK = 'TRACED_LEAK', 'Protected file traced to a recipient'
        DOWNLOAD_BURST = 'DOWNLOAD_BURST', 'Unusual download volume'

    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Critical'
        HIGH = 'HIGH', 'High'
        MEDIUM = 'MEDIUM', 'Medium'
        LOW = 'LOW', 'Low'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        ACKNOWLEDGED = 'ACKNOWLEDGED', 'Acknowledged'
        RESOLVED = 'RESOLVED', 'Resolved'

    SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    kind = models.CharField(max_length=20, choices=Kind.choices, db_index=True)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=14, choices=Status.choices, default=Status.OPEN, db_index=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                             related_name='security_alerts')     # the account involved, if any
    target = models.CharField(max_length=255, blank=True)       # file:<id>, ip:<addr>, email:<addr>...
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device = models.CharField(max_length=120, blank=True)
    first_event = models.ForeignKey('audit.AuditLog', null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name='+')
    occurrences = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(db_index=True)
    handled_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name='+')
    handled_at = models.DateTimeField(null=True, blank=True)
    note = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ('-last_seen',)

    def __str__(self):
        return '{} ({})'.format(self.title, self.get_severity_display())