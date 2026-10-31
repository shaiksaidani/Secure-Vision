"""Security Center: open alerts, blocked attempts, new devices, expired files,
and an investigation page for each alert."""
from datetime import timedelta

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.models import Device
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from vault.access import expire_due_files
from vault.models import ProtectedFile

from .models import SecurityAlert

Status = SecurityAlert.Status


@privilege_required(Privilege.VIEW_SECURITY_CENTER)
def center_view(request):
    expire_due_files()
    now = timezone.now()
    day_ago, week_ago = now - timedelta(days=1), now - timedelta(days=7)
    open_alerts = sorted(
        SecurityAlert.objects.exclude(status=Status.RESOLVED).select_related('user'),
        key=lambda a: (SecurityAlert.SEVERITY_RANK.get(a.severity, 9), -a.last_seen.timestamp()))
    blocked = AuditLog.objects.filter(result=AuditLog.Result.DENIED).select_related('user')
    return render(request, 'security/center.html', {
        'open_alerts': open_alerts,
        'metrics': {
            'critical': sum(1 for a in open_alerts if a.severity == SecurityAlert.Severity.CRITICAL),
            'high': sum(1 for a in open_alerts if a.severity == SecurityAlert.Severity.HIGH),
            'blocked_24h': blocked.filter(timestamp__gte=day_ago).count(),
            'failed_signins_24h': AuditLog.objects.filter(action=AuditLog.Action.FAILED_LOGIN,
                                                          timestamp__gte=day_ago).count(),
            'new_devices_7d': Device.objects.filter(first_registered__gte=week_ago).count(),
            'expired_files': ProtectedFile.objects.filter(status=ProtectedFile.Status.EXPIRED).count(),
        },
        'blocked': blocked[:15],
        'new_devices': Device.objects.select_related('user').filter(first_registered__gte=week_ago)[:10],
        'expired_files': ProtectedFile.objects.filter(status=ProtectedFile.Status.EXPIRED).order_by('-expires_at')[:10],
        'resolved': SecurityAlert.objects.filter(status=Status.RESOLVED).select_related('handled_by')[:8],
    })


@privilege_required(Privilege.VIEW_SECURITY_CENTER)
def alert_view(request, public_id):
    alert = get_object_or_404(SecurityAlert.objects.select_related('user', 'handled_by', 'first_event'),
                              public_id=public_id)
    start, end = alert.first_seen - timedelta(hours=2), alert.last_seen + timedelta(hours=2)
    related = AuditLog.objects.select_related('user').filter(timestamp__range=(start, end))
    if alert.user_id:
        related = related.filter(user=alert.user)
    elif alert.target.startswith('ip:'):
        related = related.filter(ip_address=alert.target[3:])
    elif alert.target.startswith('email:'):
        related = related.filter(actor_label=alert.target[6:])
    elif alert.target:
        related = related.filter(target=alert.target)
    return render(request, 'security/alert.html', {
        'alert': alert,
        'related': related.order_by('-timestamp')[:100],
        'devices': Device.objects.filter(user=alert.user) if alert.user_id else [],
    })


@privilege_required(Privilege.VIEW_SECURITY_CENTER)
@require_POST
def alert_update_view(request, public_id):
    alert = get_object_or_404(SecurityAlert, public_id=public_id)
    action = request.POST.get('action', '')
    note = (request.POST.get('note') or '').strip()[:500]
    new_status = {'acknowledge': Status.ACKNOWLEDGED, 'resolve': Status.RESOLVED, 'reopen': Status.OPEN}.get(action)
    if new_status is None:
        messages.error(request, 'Unknown action.')
        return redirect('security:alert', public_id=alert.public_id)
    old_status = alert.status
    alert.status = new_status
    alert.handled_by = request.user
    alert.handled_at = timezone.now()
    if note:
        alert.note = note
    alert.save(update_fields=['status', 'handled_by', 'handled_at', 'note'])
    log_event(AuditLog.Action.ALERT_UPDATED, request=request, target='alert:{}'.format(alert.public_id),
              details={'alert': alert.title, 'from': old_status, 'to': new_status, 'note': note})
    messages.success(request, 'Alert marked {}.'.format(alert.get_status_display().lower()))
    return redirect('security:alert', public_id=alert.public_id)