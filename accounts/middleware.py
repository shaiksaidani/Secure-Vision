from django.contrib import messages
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone

from audit.services import get_client_ip, get_user_agent

from .models import Device, UserSession


class SessionTrackingMiddleware:
    """Enforces sessions ended from another browser (or by password change)
    and keeps 'last active' up to date. Identity itself always comes from
    Django's server-side session -> request.user (the real database row)."""

    TOUCH_INTERVAL_SECONDS = 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated:
            key = request.session.session_key
            if key:
                record = UserSession.objects.filter(session_key=key).first()
                now = timezone.now()
                if record is None:
                    UserSession.objects.create(
                        user=user, session_key=key,
                        ip_address=get_client_ip(request),
                        user_agent=get_user_agent(request))
                elif record.ended_at is not None or record.user_id != user.pk:
                    request.session.flush()
                    request.user = AnonymousUser()
                    messages.warning(request, 'Your session was ended. Please sign in again.')
                elif (now - record.last_seen).total_seconds() > self.TOUCH_INTERVAL_SECONDS:
                    UserSession.objects.filter(pk=record.pk).update(last_seen=now)
                    if record.device_id:
                        Device.objects.filter(pk=record.device_id).update(last_active=now)
        return self.get_response(request)