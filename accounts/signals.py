from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone

from audit.models import AuditLog
from audit.services import get_client_ip, get_user_agent, log_event

from .models import UserSession


@receiver(user_logged_in)
def on_user_logged_in(sender, request, user, **kwargs):
    key = request.session.session_key
    if key:
        UserSession.objects.update_or_create(
            session_key=key,
            defaults={
                'user': user,
                'ip_address': get_client_ip(request),
                'user_agent': get_user_agent(request),
                'last_seen': timezone.now(),
                'ended_at': None,
                'end_reason': '',
            },
        )
    log_event(AuditLog.Action.LOGIN, request=request, user=user,
              target='user:{}'.format(user.pk))


@receiver(user_logged_out)
def on_user_logged_out(sender, request, user, **kwargs):
    if user is None:
        return
    key = request.session.session_key
    if key:
        UserSession.objects.filter(session_key=key, ended_at__isnull=True).update(
            ended_at=timezone.now(), end_reason=UserSession.EndReason.LOGOUT)
    log_event(AuditLog.Action.LOGOUT, request=request, user=user,
              target='user:{}'.format(user.pk))