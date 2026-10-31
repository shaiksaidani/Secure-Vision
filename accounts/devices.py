"""Device registration and enforcement.

How a "device" is recognised: on sign-in the browser receives a random token
in a signed, HttpOnly cookie (sv_device). The token's SHA-256 hash is stored
with the Device. Same browser + same account = same device. A new browser,
a private/incognito window, or cleared cookies count as a new device.
"""
import hashlib
import secrets

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import get_client_ip, get_user_agent, log_event

from .models import Device, DevicePolicy, UserSession
from .sessions import end_user_sessions
from .utils import describe_user_agent

COOKIE_NAME = 'sv_device'
COOKIE_SALT = 'securevision.device'
COOKIE_MAX_AGE = 365 * 24 * 60 * 60


class DeviceBlocked(Exception):
    """Sign-in refused because of the device policy."""

    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason


def _hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _kind(user_agent):
    ua = (user_agent or '').lower()
    if 'ipad' in ua or 'tablet' in ua:
        return Device.Kind.TABLET
    if 'mobi' in ua or 'iphone' in ua or 'android' in ua:
        return Device.Kind.MOBILE
    return Device.Kind.DESKTOP


def browser_token(request):
    """The token from this browser's device cookie, or None."""
    return request.get_signed_cookie(COOKIE_NAME, default=None, salt=COOKIE_SALT)


def resolve_device(request, user):
    """Called after the password is verified and BEFORE the session is created.
    Returns (device, token, created) or raises DeviceBlocked."""
    token = browser_token(request) or secrets.token_urlsafe(32)
    token_hash = _hash(token)
    with transaction.atomic():
        device = Device.objects.select_for_update().filter(user=user, token_hash=token_hash).first()
        if device is not None:
            if device.status == Device.Status.REVOKED:
                raise DeviceBlocked(
                    'This device was removed from your account, so it can no longer sign in. '
                    'Use another registered device, or ask an administrator for help.', 'revoked_device')
            return device, token, False
        limit = DevicePolicy.current().max_devices_per_user
        in_use = Device.objects.filter(user=user, status=Device.Status.ACTIVE).count()
        if in_use >= limit:
            raise DeviceBlocked(
                'Your account already has {} registered device{}, the maximum allowed. Remove one '
                'from Profile on a device you already use, or ask an administrator.'.format(
                    limit, '' if limit == 1 else 's'), 'device_limit')
        user_agent = get_user_agent(request)
        device = Device.objects.create(
            user=user, token_hash=token_hash, name=describe_user_agent(user_agent),
            kind=_kind(user_agent), user_agent=user_agent, last_ip=get_client_ip(request))
    return device, token, True


def bind_session(request, device):
    """Link the just-created session to the device."""
    UserSession.objects.filter(session_key=request.session.session_key).update(device=device)
    Device.objects.filter(pk=device.pk).update(last_active=timezone.now(),
                                               last_ip=get_client_ip(request))


def set_cookie(response, token):
    response.set_signed_cookie(
        COOKIE_NAME, token, salt=COOKIE_SALT, max_age=COOKIE_MAX_AGE, httponly=True,
        samesite='Lax', secure=getattr(settings, 'SESSION_COOKIE_SECURE', False))
    return response


def current_device_id(request):
    return (UserSession.objects.filter(session_key=request.session.session_key)
            .values_list('device_id', flat=True).first())


def revoke(device, request):
    """Remove a device: it can no longer sign in and its sessions end now."""
    if device.status == Device.Status.REVOKED:
        return 0
    device.status = Device.Status.REVOKED
    device.revoked_at = timezone.now()
    device.revoked_by = request.user
    device.save(update_fields=['status', 'revoked_at', 'revoked_by'])
    session_ids = list(UserSession.objects.filter(device=device, ended_at__isnull=True)
                       .values_list('pk', flat=True))
    ended = end_user_sessions(device.user, UserSession.EndReason.DEVICE_REVOKED, only_pks=session_ids)
    log_event(AuditLog.Action.DEVICE_REVOKED, request=request,
              target='device:{}'.format(device.public_id),
              details={'user': device.user.email, 'device': device.name, 'sessions_ended': ended})
    return ended