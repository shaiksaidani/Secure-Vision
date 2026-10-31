"""Activity Logs: the full audit timeline for administrators, and each
person's own activity for everyone else."""
import csv
import datetime as dt

from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from accounts.utils import describe_user_agent

from .models import AuditLog
from .services import log_event


def _parse_date(value):
    try:
        return dt.datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None


def _day_bounds(day, end=False):
    moment = dt.datetime.combine(day, dt.time.max if end else dt.time.min)
    return timezone.make_aware(moment, timezone.get_current_timezone())


@privilege_required(Privilege.VIEW_DASHBOARD)
def activity_view(request):
    org_view = request.user.has_privilege(Privilege.VIEW_AUDIT_LOGS)
    events = AuditLog.objects.select_related('user')
    if not org_view:
        events = events.filter(user=request.user)

    query = request.GET.get('q', '').strip()
    action = request.GET.get('action', '')
    result = request.GET.get('result', '')
    date_from = _parse_date(request.GET.get('from'))
    date_to = _parse_date(request.GET.get('to'))
    if query and org_view:
        events = events.filter(Q(actor_label__icontains=query) | Q(target__icontains=query)
                               | Q(ip_address__icontains=query) | Q(user__full_name__icontains=query))
    if action in AuditLog.Action.values:
        events = events.filter(action=action)
    if result in AuditLog.Result.values:
        events = events.filter(result=result)
    if date_from:
        events = events.filter(timestamp__gte=_day_bounds(date_from))
    if date_to:
        events = events.filter(timestamp__lte=_day_bounds(date_to, end=True))

    if org_view and request.GET.get('export') == 'csv':
        log_event(AuditLog.Action.AUDIT_EXPORTED, request=request, target='audit:export',
                  details={'q': query, 'action': action, 'result': result,
                           'from': str(date_from or ''), 'to': str(date_to or '')})
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="securevision_activity.csv"'
        writer = csv.writer(response)
        writer.writerow(['Event ID', 'Time', 'Account', 'Action', 'Target', 'Result', 'IP', 'Device', 'Session'])
        for event in events[:10000]:
            writer.writerow([event.event_id, timezone.localtime(event.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                             event.actor_label, event.get_action_display(), event.target,
                             event.get_result_display(), event.ip_address or '',
                             describe_user_agent(event.user_agent) if event.user_agent else '',
                             event.session_ref])
        return response

    page = Paginator(events, 50).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'audit/activity.html', {
        'org_view': org_view, 'page': page, 'query': query, 'action': action, 'result': result,
        'date_from': date_from, 'date_to': date_to,
        'actions': AuditLog.Action.choices, 'results': AuditLog.Result.choices,
        'querystring': params.urlencode(),
    })