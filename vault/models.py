"""Protected files. Security metadata (hash, grants, expiry, watermark
settings) lives in the database, completely separate from the file's
content, which is stored encrypted and never modified."""
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class ProtectedFile(models.Model):

    class Category(models.TextChoices):
        IMAGE = 'IMAGE', 'Images'
        VIDEO = 'VIDEO', 'Videos'
        AUDIO = 'AUDIO', 'Audio'
        PDF = 'PDF', 'PDFs'
        TEXT = 'TEXT', 'Text files'
        DOCUMENT = 'DOCUMENT', 'Documents'

    class Status(models.TextChoices):
        ACTIVE = 'ACTIVE', 'Active'
        EXPIRED = 'EXPIRED', 'Expired'

    # Unguessable ID used in every URL (never the sequential pk).
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=1000)
    original_filename = models.CharField(max_length=255)
    extension = models.CharField(max_length=10)
    category = models.CharField(max_length=10, choices=Category.choices, db_index=True)
    mime_type = models.CharField(max_length=120)
    size_bytes = models.BigIntegerField()
    sha256 = models.CharField(max_length=64, db_index=True)
    storage_name = models.CharField(max_length=64, unique=True)  # never shown to users

    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name='uploaded_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    expires_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE,
                              db_index=True)

    # Access grants: a user may open the file if they are listed directly or
    # belong to one of the allowed teams. Admins can always manage it.
    allowed_teams = models.ManyToManyField('teams.Team', blank=True, related_name='protected_files')
    allowed_users = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True,
                                           related_name='granted_files')
    allow_download = models.BooleanField(default=False)
    visible_watermark = models.BooleanField(default=True)
    # Images: each recipient gets a copy with an invisible watermark naming them.
    forensic_watermark = models.BooleanField(default=True)
    # Visual fingerprint of images, used to recognise modified copies.
    perceptual_hash = models.CharField(max_length=16, blank=True)

    class Meta:
        ordering = ('-uploaded_at',)

    def __str__(self):
        return self.title

    @property
    def is_past_expiry(self):
        return self.expires_at is not None and self.expires_at <= timezone.now()

    @property
    def expires_soon(self):
        if self.expires_at is None or self.is_past_expiry:
            return False
        days = getattr(settings, 'SV_EXPIRY_WARNING_DAYS', 7)
        return self.expires_at <= timezone.now() + timedelta(days=days)

    @property
    def size_label(self):
        size = float(self.size_bytes)
        for unit in ('bytes', 'KB', 'MB', 'GB'):
            if size < 1024 or unit == 'GB':
                return '{:.0f} {}'.format(size, unit) if unit == 'bytes' else '{:.1f} {}'.format(size, unit)
            size /= 1024.0

    @property
    def icon(self):
        return {
            'IMAGE': 'image', 'VIDEO': 'video', 'AUDIO': 'audio',
            'PDF': 'file', 'TEXT': 'file', 'DOCUMENT': 'file',
        }.get(self.category, 'file')
        

class AccessRequest(models.Model):
    """An employee asking for access to a file they can't open."""

    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        APPROVED = 'APPROVED', 'Approved'
        REJECTED = 'REJECTED', 'Rejected'

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    file = models.ForeignKey(ProtectedFile, on_delete=models.CASCADE, related_name='access_requests')
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                  related_name='access_requests')
    reason = models.TextField(max_length=500)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name='+')
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return '{} -> {} ({})'.format(self.requester, self.file, self.status)