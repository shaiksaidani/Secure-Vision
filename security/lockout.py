"""Temporary sign-in lockout after repeated failed attempts, computed from
the audit log (so it survives restarts and works per email address)."""
import math
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from audit.models import AuditLog


def lock_status(email):
    """(locked, minutes_left) for this email address."""
    attempts = settings.SV_LOCKOUT_ATTEMPTS
    window = timedelta(minutes=settings.SV_LOCKOUT_MINUTES)
    now = timezone.now()
    since = now - window
    last_success = (AuditLog.objects.filter(action=AuditLog.Action.LOGIN, actor_label=email)
                    .order_by('-timestamp').values_list('timestamp', flat=True).first())
    if last_success and last_success > since:
        since = last_success
    recent_failures = list(
        AuditLog.objects.filter(action=AuditLog.Action.FAILED_LOGIN, result=AuditLog.Result.FAILURE,
                                actor_label=email, timestamp__gt=since)
        .order_by('-timestamp').values_list('timestamp', flat=True)[:attempts])
    if len(recent_failures) < attempts:
        return False, 0
    unlock_at = recent_failures[-1] + window      # when the oldest counted failure expires
    seconds = (unlock_at - now).total_seconds()
    if seconds <= 0:
        return False, 0
    return True, max(1, int(math.ceil(seconds / 60.0)))