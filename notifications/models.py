"""Per-user notifications. Every notification belongs to a real user."""
from django.conf import settings
from django.db import models


class Notification(models.Model):

    class Kind(models.TextChoices):
        ACCESS = 'ACCESS', 'File access'
        EXPIRY = 'EXPIRY', 'File expiry'
        ANNOUNCEMENT = 'ANNOUNCEMENT', 'Team announcement'
        ATTENDANCE = 'ATTENDANCE', 'Attendance'
        REQUEST = 'REQUEST', 'Access request'
        SECURITY = 'SECURITY', 'Security'

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    kind = models.CharField(max_length=14, choices=Kind.choices)
    title = models.CharField(max_length=200)
    body = models.CharField(max_length=500, blank=True)
    url = models.CharField(max_length=300, blank=True)          # an internal path, e.g. /files/<id>/
    object_ref = models.CharField(max_length=100, blank=True, db_index=True)   # for "send once" checks
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ('-created_at', '-id')
        indexes = [models.Index(fields=['user', 'read_at'])]

    def __str__(self):
        return '{}: {}'.format(self.user, self.title)

    @property
    def is_read(self):
        return self.read_at is not None