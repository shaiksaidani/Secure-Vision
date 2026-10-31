"""The single entry point every module uses to write audit events."""
import hashlib
import ipaddress
import json
import logging

from django.conf import settings

from .models import AuditLog

logger = logging.getLogger('securevision.audit')


def session_fingerprint(session_key):
    if not session_key:
        return ''
    return hashlib.sha256(session_key.encode('utf-8')).hexdigest()[:16]


def get_client_ip(request):
    """REMOTE_ADDR by default. X-Forwarded-For is only trusted when the app is
    explicitly configured to run behind a trusted proxy (it is spoofable)."""
    candidate = None
    if getattr(settings, 'SV_TRUST_X_FORWARDED_FOR', False):
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            candidate = forwarded.split(',')[0].strip()
    if not candidate:
        candidate = request.META.get('REMOTE_ADDR')
    try:
        return str(ipaddress.ip_address(candidate)) if candidate else None
    except ValueError:
        return None


def get_user_agent(request):
    return (request.META.get('HTTP_USER_AGENT') or '')[:300]


def log_event(action, request=None, user=None, target='',
              result=AuditLog.Result.SUCCESS, details=None, actor_label=''):
    """Record an audit event.

    user defaults to the authenticated request.user. Never pass passwords,
    tokens or file contents in details.
    """
    if user is None and request is not None:
        request_user = getattr(request, 'user', None)
        if request_user is not None and request_user.is_authenticated:
            user = request_user
    if not actor_label and user is not None:
        actor_label = user.email

    ip_address = user_agent = session_ref = ''
    if request is not None:
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        session = getattr(request, 'session', None)
        session_ref = session_fingerprint(session.session_key if session is not None else '')

    try:
        return AuditLog.objects.create(
            user=user,
            actor_label=(actor_label or '')[:254],
            action=action,
            target=(target or '')[:255],
            result=result,
            ip_address=ip_address or None,
            user_agent=user_agent or '',
            session_ref=session_ref or '',
            details=json.dumps(details, default=str) if details else '',
        )
    except Exception:  # never let an audit failure crash a user request
        logger.exception('Failed to write audit event %s', action)
        return None