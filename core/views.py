from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils import timezone

from accounts.permissions import Privilege
from accounts.sessions import active_sessions_for
from attendance import services as attendance
from attendance.models import AttendanceRecord
from audit.models import AuditLog
from teams.models import Team
from vault.access import expire_due_files, files_visible_to
from vault.models import ProtectedFile

User = get_user_model()


def home_view(request):
    if request.user.is_authenticated:
        return redirect('core:dashboard')
    return redirect('accounts:login')


@login_required
def dashboard_view(request):
    user = request.user  # always the real database user from the session
    now = timezone.now()
    expire_due_files()

    # Organization-wide figures for admins, personal figures for everyone else.
    org_view = user.has_privilege(Privilege.VIEW_AUDIT_LOGS)
    visible_files = files_visible_to(user)
    soon = now + timedelta(days=settings.SV_EXPIRY_WARNING_DAYS)
    workspace = {
        'files': visible_files.count(),
        'expiring': visible_files.filter(status=ProtectedFile.Status.ACTIVE,
                                         expires_at__gt=now, expires_at__lte=soon).count(),
        'teams': Team.objects.count() if org_view else user.teams.count(),
        'active_users': User.objects.filter(is_active=True).count() if org_view else None,
    }
        # Today's attendance: organization-wide for admins, personal otherwise.
    today = attendance.today()
    if org_view:
        attendance_today = {
            'checked_in': AttendanceRecord.objects.filter(date=today, check_in_at__isnull=False,
                                                          user__is_active=True).count(),
            'late': AttendanceRecord.objects.filter(date=today, status=AttendanceRecord.Status.LATE).count(),
        }
    else:
        record = AttendanceRecord.objects.filter(user=user, date=today).first()
        code, label = attendance.day_status(record, today, today)
        attendance_today = {'record': record, 'code': code, 'label': label}

    security_overview = None
    if org_view:
        from incidents.models import Incident
        from security.models import SecurityAlert
        from vault.models import AccessRequest
        open_alerts = SecurityAlert.objects.filter(status=SecurityAlert.Status.OPEN)
        security_overview = {
            'open_alerts': open_alerts.count(),
            'serious_alerts': open_alerts.filter(severity__in=[SecurityAlert.Severity.CRITICAL,
                                                               SecurityAlert.Severity.HIGH]).count(),
            'active_incidents': Incident.objects.filter(status__in=Incident.ACTIVE_STATUSES).count(),
            'my_incidents': Incident.objects.filter(status__in=Incident.ACTIVE_STATUSES, assigned_to=user).count(),
            'pending_requests': AccessRequest.objects.filter(status=AccessRequest.Status.PENDING).count(),
        }
    logins = AuditLog.objects.filter(user=user, action=AuditLog.Action.LOGIN)
    previous_login = logins[1] if logins.count() > 1 else None
    if org_view:
        recent_events = AuditLog.objects.select_related('user')[:10]
    else:
        recent_events = AuditLog.objects.filter(user=user)[:8]

    return render(request, 'core/dashboard.html', {
        'org_view': org_view,
        'workspace': workspace,
        'attendance_today': attendance_today,
        'security_overview': security_overview,
        'recent_events': recent_events,
        'active_session_count': active_sessions_for(user).count(),
        'failed_signins_week': AuditLog.objects.filter(
            user=user, action=AuditLog.Action.FAILED_LOGIN,
            timestamp__gte=now - timedelta(days=7)).count(),
        'previous_login': previous_login,
    })


def csrf_failure(request, reason=''):
    return render(request, '403_csrf.html', status=403)