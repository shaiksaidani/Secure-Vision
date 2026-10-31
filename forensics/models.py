"""Watermarks issued to recipients, and forensic analyses of suspicious files."""
import json
import uuid

from django.conf import settings
from django.db import models


class Watermark(models.Model):
    """One personalised, invisibly marked copy of a protected image.
    Same person + file + purpose + day reuses the same watermark."""

    class Purpose(models.TextChoices):
        VIEW = 'VIEW', 'Viewed in the secure viewer'
        DOWNLOAD = 'DOWNLOAD', 'Downloaded'

    code = models.CharField(max_length=12, unique=True)   # 48-bit hex ID hidden in the pixels
    file = models.ForeignKey('vault.ProtectedFile', on_delete=models.CASCADE, related_name='watermarks')
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                                  related_name='watermarks')
    purpose = models.CharField(max_length=10, choices=Purpose.choices)
    issued_on = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_served_at = models.DateTimeField(null=True, blank=True)
    times_served = models.PositiveIntegerField(default=0)
    served_sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_name = models.CharField(max_length=120, blank=True)
    session_ref = models.CharField(max_length=16, blank=True)

    class Meta:
        ordering = ('-created_at',)
        constraints = [
            models.UniqueConstraint(fields=['file', 'recipient', 'purpose', 'issued_on'],
                                    name='one_watermark_per_recipient_purpose_day'),
        ]

    def __str__(self):
        return '{} -> {}'.format(self.code, self.recipient)


class ForensicAnalysis(models.Model):

    class Tampered(models.TextChoices):
        DETECTED = 'DETECTED', 'Detected'
        NOT_DETECTED = 'NOT_DETECTED', 'Not detected'
        INCONCLUSIVE = 'INCONCLUSIVE', 'Inconclusive'

    class WatermarkStatus(models.TextChoices):
        FOUND = 'FOUND', 'Found'
        NOT_FOUND = 'NOT_FOUND', 'Not detected'
        NOT_APPLICABLE = 'NOT_APPLICABLE', 'Not applicable to this file type'

    class Risk(models.TextChoices):
        HIGH = 'HIGH', 'High'
        MEDIUM = 'MEDIUM', 'Medium'
        LOW = 'LOW', 'Low'

    class Evidence(models.TextChoices):
        AVAILABLE = 'AVAILABLE', 'Evidence available'
        INSUFFICIENT = 'INSUFFICIENT', 'Insufficient evidence'

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    analyst = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                                related_name='forensic_analyses')
    created_at = models.DateTimeField(auto_now_add=True)
    sample_name = models.CharField(max_length=255)
    sample_size = models.BigIntegerField()
    sample_sha256 = models.CharField(max_length=64, db_index=True)
    sample_storage = models.CharField(max_length=64, blank=True)  # encrypted copy kept as evidence
    matched_file = models.ForeignKey('vault.ProtectedFile', null=True, blank=True,
                                     on_delete=models.SET_NULL, related_name='+')
    watermark = models.ForeignKey(Watermark, null=True, blank=True, on_delete=models.SET_NULL,
                                  related_name='analyses')
    associated_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                        on_delete=models.SET_NULL, related_name='+')
    tampered = models.CharField(max_length=14, choices=Tampered.choices)
    watermark_status = models.CharField(max_length=16, choices=WatermarkStatus.choices)
    risk = models.CharField(max_length=8, choices=Risk.choices)
    evidence = models.CharField(max_length=14, choices=Evidence.choices)
    summary = models.TextField()
    details = models.TextField(blank=True)  # JSON: findings, timeline, devices, events

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return 'Analysis of {} ({})'.format(self.sample_name, self.created_at)

    @property
    def details_dict(self):
        try:
            return json.loads(self.details) if self.details else {}
        except ValueError:
            return {}