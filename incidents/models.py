"""Incidents, their append-only timeline, and the Evidence Vault.

Evidence is stored encrypted (same protection as Stored Data). Evidence and
custody records can never be edited or deleted through the application, so
the chain of custody stays intact."""
import uuid

from django.conf import settings
from django.db import models


class AppendOnly(models.Model):
    """Rows that may be created but never changed or deleted."""

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError('{} records are append-only.'.format(self.__class__.__name__))
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError('{} records cannot be deleted.'.format(self.__class__.__name__))


class Incident(models.Model):

    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Critical'
        HIGH = 'HIGH', 'High'
        MEDIUM = 'MEDIUM', 'Medium'
        LOW = 'LOW', 'Low'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        INVESTIGATING = 'INVESTIGATING', 'Investigating'
        CONTAINED = 'CONTAINED', 'Contained'
        RESOLVED = 'RESOLVED', 'Resolved'
        CLOSED = 'CLOSED', 'Closed'

    ACTIVE_STATUSES = ('OPEN', 'INVESTIGATING', 'CONTAINED')

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    reference = models.CharField(max_length=20, unique=True)           # INC-2026-0001
    title = models.CharField(max_length=200)
    summary = models.TextField(max_length=4000, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=14, choices=Status.choices, default=Status.OPEN, db_index=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                                   related_name='+')
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name='assigned_incidents')
    subject_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                     related_name='+')                    # the person involved, if any
    related_file = models.ForeignKey('vault.ProtectedFile', null=True, blank=True, on_delete=models.SET_NULL,
                                     related_name='incidents')
    alerts = models.ManyToManyField('security.SecurityAlert', blank=True, related_name='incidents')
    analyses = models.ManyToManyField('forensics.ForensicAnalysis', blank=True, related_name='incidents')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return '{} {}'.format(self.reference, self.title)

    @property
    def is_active(self):
        return self.status in self.ACTIVE_STATUSES


class IncidentEntry(AppendOnly):
    """One line in an incident's timeline."""

    class Kind(models.TextChoices):
        CREATED = 'CREATED', 'Incident opened'
        NOTE = 'NOTE', 'Note'
        STATUS = 'STATUS', 'Status changed'
        SEVERITY = 'SEVERITY', 'Severity changed'
        ASSIGNED = 'ASSIGNED', 'Assignment changed'
        EVIDENCE = 'EVIDENCE', 'Evidence added'
        LINKED = 'LINKED', 'Linked record'

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='entries')
    kind = models.CharField(max_length=10, choices=Kind.choices)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name='+')
    text = models.TextField(max_length=4000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('created_at', 'id')


class Evidence(AppendOnly):

    class Kind(models.TextChoices):
        UPLOAD = 'UPLOAD', 'Uploaded file'
        FORENSIC_SAMPLE = 'FORENSIC_SAMPLE', 'Forensic sample'
        ACTIVITY_SNAPSHOT = 'ACTIVITY_SNAPSHOT', 'Activity log snapshot'

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    reference = models.CharField(max_length=30, unique=True)           # INC-2026-0001-E01
    incident = models.ForeignKey(Incident, on_delete=models.PROTECT, related_name='evidence')
    kind = models.CharField(max_length=18, choices=Kind.choices)
    title = models.CharField(max_length=200)
    description = models.TextField(max_length=2000, blank=True)
    original_filename = models.CharField(max_length=255)
    mime_type = models.CharField(max_length=100, default='application/octet-stream')
    size_bytes = models.BigIntegerField()
    sha256 = models.CharField(max_length=64)
    storage_name = models.CharField(max_length=64, unique=True)
    source_ref = models.CharField(max_length=100, blank=True)          # e.g. analysis:<id>
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name='+')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('added_at', 'id')

    def __str__(self):
        return '{} {}'.format(self.reference, self.title)


class CustodyRecord(AppendOnly):
    """Chain of custody: every time evidence is added, opened or verified."""

    class Action(models.TextChoices):
        ADDED = 'ADDED', 'Added to the vault'
        DOWNLOADED = 'DOWNLOADED', 'Downloaded'
        VERIFIED = 'VERIFIED', 'Integrity verified'
        VERIFY_FAILED = 'VERIFY_FAILED', 'Integrity check FAILED'

    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, related_name='custody')
    action = models.CharField(max_length=14, choices=Action.choices)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name='+')
    actor_label = models.CharField(max_length=254, blank=True)
    at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device = models.CharField(max_length=120, blank=True)
    sha256_observed = models.CharField(max_length=64, blank=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ('at', 'id')