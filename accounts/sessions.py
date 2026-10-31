"""Helpers for ending sessions server-side. Deleting the Session row is what
actually signs a browser out; UserSession keeps the visible history."""
from django.contrib.sessions.models import Session
from django.utils import timezone

from .models import UserSession


def end_user_sessions(user, reason, exclude_key=None, only_pks=None):
    qs = UserSession.objects.filter(user=user, ended_at__isnull=True)
    if exclude_key:
        qs = qs.exclude(session_key=exclude_key)
    if only_pks is not None:
        qs = qs.filter(pk__in=only_pks)
    keys = list(qs.values_list('session_key', flat=True))
    if not keys:
        return 0
    Session.objects.filter(session_key__in=keys).delete()
    UserSession.objects.filter(session_key__in=keys).update(
        ended_at=timezone.now(), end_reason=reason)
    return len(keys)


def active_sessions_for(user):
    """Open sessions whose server-side session still exists and hasn't expired.
    Stale records are closed as EXPIRED on the way."""
    now = timezone.now()
    open_qs = UserSession.objects.filter(user=user, ended_at__isnull=True)
    keys = list(open_qs.values_list('session_key', flat=True))
    live = set(Session.objects.filter(
        session_key__in=keys, expire_date__gt=now).values_list('session_key', flat=True))
    stale = [k for k in keys if k not in live]
    if stale:
        UserSession.objects.filter(session_key__in=stale).update(
            ended_at=now, end_reason=UserSession.EndReason.EXPIRED)
    return UserSession.objects.filter(user=user, ended_at__isnull=True).order_by('-last_seen')