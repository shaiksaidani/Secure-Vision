"""Detection rules. Every new audit event is checked here; matching patterns
raise (or update) a SecurityAlert and notify the security team once."""
import json
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from accounts.permissions import Privilege
from accounts.utils import describe_user_agent
from audit.models import AuditLog
from notifications.models import Notification
from notifications.services import notify_many, users_with_privilege

from .models import SecurityAlert

logger = logging.getLogger('securevision.security')
User = get_user_model()
Action = AuditLog.Action
Kind = SecurityAlert.Kind
Severity = SecurityAlert.Severity


def raise_alert(entry, kind, severity, title, description, user=None, target='', dedupe_minutes=60):
    """Create an alert, or count another occurrence of a recent open one."""
    now = timezone.now()
    existing = (SecurityAlert.objects
                .filter(kind=kind, user=user, target=target, last_seen__gte=now - timedelta(minutes=dedupe_minutes))
                .exclude(status=SecurityAlert.Status.RESOLVED).first())
    if existing:
        SecurityAlert.objects.filter(pk=existing.pk).update(
            occurrences=existing.occurrences + 1, last_seen=now, description=description)
        return existing, False
    alert = SecurityAlert.objects.create(
        kind=kind, severity=severity, title=title, description=description, user=user, target=target,
        ip_address=entry.ip_address, device=describe_user_agent(entry.user_agent) if entry.user_agent else '',
        first_event=entry, last_seen=now)
    notify_many(users_with_privilege(Privilege.VIEW_SECURITY_CENTER), Notification.Kind.SECURITY,
                'Security alert: {}'.format(title), description[:300],
                url=reverse('security:alert', args=[alert.public_id]))
    return alert, True


def _recent(window_minutes, **filters):
    return AuditLog.objects.filter(timestamp__gte=timezone.now() - timedelta(minutes=window_minutes), **filters)


def evaluate(entry):
    action = entry.action
    who = entry.user.full_name if entry.user else (entry.actor_label or 'unknown')

    if action == Action.ACCOUNT_LOCKED:
        raise_alert(entry, Kind.ACCOUNT_LOCKED, Severity.HIGH,
                    'Account locked after repeated failed sign-ins',
                    '{} reached {} failed sign-in attempts. Sign-in is blocked for {} minutes.'.format(
                        entry.actor_label, settings.SV_LOCKOUT_ATTEMPTS, settings.SV_LOCKOUT_MINUTES),
                    user=entry.user, target='email:{}'.format(entry.actor_label))

    elif action == Action.FAILED_LOGIN and entry.result == AuditLog.Result.FAILURE and entry.ip_address:
        failures = _recent(15, action=Action.FAILED_LOGIN, ip_address=entry.ip_address)
        accounts = failures.values('actor_label').distinct().count()
        if failures.count() >= settings.SV_SPRAY_ALERT_THRESHOLD and accounts >= 3:
            raise_alert(entry, Kind.SIGNIN_SPRAY, Severity.HIGH, 'Many failed sign-ins from one address',
                        '{} failed sign-ins against {} different accounts from {} in 15 minutes.'.format(
                            failures.count(), accounts, entry.ip_address),
                        target='ip:{}'.format(entry.ip_address))

    elif action == Action.ACCESS_DENIED and entry.user is not None:
        denials = _recent(10, action=Action.ACCESS_DENIED, user=entry.user).count()
        if denials >= settings.SV_DENIAL_ALERT_THRESHOLD:
            raise_alert(entry, Kind.REPEATED_DENIALS, Severity.HIGH, 'Multiple denied access attempts',
                        '{} was denied access {} times in 10 minutes. Latest: {}.'.format(
                            who, denials, entry.target or 'a protected page'),
                        user=entry.user)

    elif action == Action.DEVICE_BLOCKED:
        raise_alert(entry, Kind.DEVICE_BLOCKED, Severity.MEDIUM, 'Sign-in blocked by device policy',
                    '{} tried to sign in from a device that is over the limit or was removed.'.format(who),
                    user=entry.user)

    elif action == Action.INTEGRITY_FAILURE:
        raise_alert(entry, Kind.INTEGRITY_FAILURE, Severity.CRITICAL, 'Protected file failed its integrity check',
                    'The stored copy of {} is missing or does not match its recorded hash. It was blocked when {} '
                    'tried to open it.'.format(entry.target, who),
                    target=entry.target, dedupe_minutes=24 * 60)

    elif action == Action.FORENSIC_ANALYSIS:
        details = entry.details_dict
        if details.get('risk') == 'HIGH':
            traced = User.objects.filter(email=details.get('associated_user')).first()
            raise_alert(entry, Kind.TRACED_LEAK, Severity.HIGH, 'Protected file traced to a recipient',
                        'Forensic analysis of "{}" traced it to {}.'.format(
                            details.get('sample', 'a sample'),
                            traced.full_name if traced else 'a recipient'),
                        user=traced, target=entry.target)

    elif action == Action.FILE_DOWNLOAD and entry.user is not None:
        downloads = _recent(10, action=Action.FILE_DOWNLOAD, user=entry.user).count()
        if downloads >= settings.SV_DOWNLOAD_ALERT_THRESHOLD:
            raise_alert(entry, Kind.DOWNLOAD_BURST, Severity.MEDIUM, 'Unusual download volume',
                        '{} downloaded {} protected files in 10 minutes.'.format(who, downloads),
                        user=entry.user)


def safe_evaluate(entry):
    try:
        evaluate(entry)
    except Exception:  # detection must never break the action being audited
        logger.exception('Security rule evaluation failed for audit event %s', entry.pk)