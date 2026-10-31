"""Attendance: one record per user per day, always tied to the real user."""
from django.conf import settings
from django.db import models
from django.utils import timezone


def format_duration(delta):
    if delta is None:
        return ''
    minutes = max(int(delta.total_seconds() // 60), 0)
    return '{}h {:02d}m'.format(minutes // 60, minutes % 60)


class AttendanceRecord(models.Model):

    class Status(models.TextChoices):
        PRESENT = 'PRESENT', 'Present'
        LATE = 'LATE', 'Late'
        LEAVE = 'LEAVE', 'Leave'
        ABSENT = 'ABSENT', 'Absent'

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='attendance_records')
    date = models.DateField(db_index=True)  # the user's local calendar day
    status = models.CharField(max_length=10, choices=Status.choices)
    check_in_at = models.DateTimeField(null=True, blank=True)
    check_out_at = models.DateTimeField(null=True, blank=True)
    check_in_ip = models.GenericIPAddressField(null=True, blank=True)
    check_in_device = models.CharField(max_length=120, blank=True)
    check_out_device = models.CharField(max_length=120, blank=True)
    session_ref = models.CharField(max_length=16, blank=True)
    # Leave / absence recorded by an administrator.
    note = models.CharField(max_length=255, blank=True)
    marked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                  on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-date',)
        constraints = [
            models.UniqueConstraint(fields=['user', 'date'], name='one_attendance_record_per_day'),
        ]

    def __str__(self):
        return '{} {} {}'.format(self.user, self.date, self.status)

    @property
    def worked(self):
        """Time between check-in and check-out (or now, while still checked in today)."""
        if self.check_in_at is None:
            return None
        end = self.check_out_at
        if end is None:
            if self.date != timezone.localdate():
                return None  # never checked out that day
            end = timezone.now()
        return end - self.check_in_at

    @property
    def worked_label(self):
        return format_duration(self.worked)