"""Reports built from real records: a security summary for a period and a
protected-file access report. Both export to CSV; exports are audited."""
import csv
from datetime import timedelta

from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from incidents.models import Incident
from security.models import SecurityAlert
from vault.models import ProtectedFile

A = AuditLog.Action
PERIODS = [(7, 'Last 7 days'), (30, 'Last 30 days'), (90, 'Last 90 days')]


def _period(request):
    try:
        days = int(request.GET.get('days', 30))
    except (TypeError, ValueError):
        days = 30
    return days if days in dict(PERIODS) else 30


def _csv(request, filename, header, rows, report):
    log_event(A.REPORT_GENERATED, request=request, target='report:{}'.format(report),
              details={'report': report, 'rows': len(rows), 'format': 'csv'})
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="{}"'.format(filename)
    writer = csv.writer(response)
    writer.writerow(header)
    writer.writerows(rows)
    return response


@privilege_required(Privilege.VIEW_REPORTS)
def summary_view(request):
    days = _period(request)
    since = timezone.now() - timedelta(days=days)
    events = AuditLog.objects.filter(timestamp__gte=since)
    counts = dict(events.order_by().values_list('action').annotate(n=Count('id')))

    def total(*actions):
        return sum(counts.get(action, 0) for action in actions)

    sections = [
        ('Sign-in and devices', [
            ('Successful sign-ins', total(A.LOGIN)), ('Failed sign-ins', total(A.FAILED_LOGIN)),
            ('Accounts locked', total(A.ACCOUNT_LOCKED)), ('New devices registered', total(A.DEVICE_REGISTERED)),
            ('Sign-ins blocked by device policy', total(A.DEVICE_BLOCKED))]),
        ('Protected files', [
            ('Files uploaded', total(A.FILE_UPLOAD)), ('Files viewed', total(A.FILE_VIEW)),
            ('Files downloaded', total(A.FILE_DOWNLOAD)), ('Access denied', total(A.ACCESS_DENIED)),
            ('Permission changes', total(A.PERMISSION_CHANGED)), ('Files expired', total(A.FILE_EXPIRED)),
            ('Integrity failures', total(A.INTEGRITY_FAILURE))]),
        ('Access requests', [
            ('Requested', total(A.ACCESS_REQUEST)), ('Approved', total(A.ACCESS_APPROVED)),
            ('Rejected', total(A.ACCESS_REJECTED))]),
        ('Investigations', [
            ('Forensic analyses', total(A.FORENSIC_ANALYSIS)), ('Incidents opened', total(A.INCIDENT_CREATED)),
            ('Evidence items added', total(A.EVIDENCE_ADDED))]),
    ]
    alerts = dict(SecurityAlert.objects.filter(first_seen__gte=since).order_by()
                  .values_list('severity').annotate(n=Count('id')))
    alert_rows = [(label, alerts.get(value, 0)) for value, label in SecurityAlert.Severity.choices]
    incident_rows = [(label, Incident.objects.filter(status=value).count())
                     for value, label in Incident.Status.choices]

    if request.GET.get('export') == 'csv':
        rows = [(section, label, value) for section, items in sections for label, value in items]
        rows += [('Security alerts raised', label, value) for label, value in alert_rows]
        rows += [('Incidents by status (all time)', label, value) for label, value in incident_rows]
        return _csv(request, 'securevision_summary_{}d.csv'.format(days), ['Section', 'Measure', 'Value'],
                    rows, 'summary')

    top_denied = (events.filter(action=A.ACCESS_DENIED, user__isnull=False).order_by()
                  .values('user__full_name', 'user__email').annotate(n=Count('id')).order_by('-n')[:5])
    file_counts = (events.filter(action__in=[A.FILE_VIEW, A.FILE_DOWNLOAD], target__startswith='file:')
                   .order_by().values('target').annotate(n=Count('id')).order_by('-n')[:5])
    titles = {'file:{}'.format(f.public_id): f.title for f in ProtectedFile.objects.filter(
        public_id__in=[row['target'][5:] for row in file_counts])}
    top_files = [{'title': titles.get(row['target'], row['target']), 'n': row['n']} for row in file_counts]
    return render(request, 'reports/summary.html', {
        'days': days, 'periods': PERIODS, 'since': since, 'sections': sections, 'alert_rows': alert_rows,
        'incident_rows': incident_rows, 'top_denied': top_denied, 'top_files': top_files,
        'total_events': events.count(),
    })


@privilege_required(Privilege.VIEW_REPORTS)
def file_access_view(request):
    days = _period(request)
    since = timezone.now() - timedelta(days=days)
    events = AuditLog.objects.filter(timestamp__gte=since, target__startswith='file:')
    per_file = {}
    for target, action, actor in events.values_list('target', 'action', 'actor_label'):
        row = per_file.setdefault(target, {'views': 0, 'downloads': 0, 'denied': 0, 'people': set()})
        if action == A.FILE_VIEW:
            row['views'] += 1
            row['people'].add(actor)
        elif action == A.FILE_DOWNLOAD:
            row['downloads'] += 1
            row['people'].add(actor)
        elif action == A.ACCESS_DENIED:
            row['denied'] += 1
    rows = []
    for item in ProtectedFile.objects.select_related('uploaded_by').order_by('title'):
        stats = per_file.get('file:{}'.format(item.public_id), {'views': 0, 'downloads': 0, 'denied': 0,
                                                                  'people': set()})
        rows.append({'file': item, 'views': stats['views'], 'downloads': stats['downloads'],
                     'denied': stats['denied'], 'people': sorted(stats['people'])})
    if request.GET.get('export') == 'csv':
        return _csv(request, 'securevision_file_access_{}d.csv'.format(days),
                    ['File', 'Status', 'Views', 'Downloads', 'Denied attempts', 'People who opened it', 'SHA-256'],
                    [(r['file'].title, r['file'].get_status_display(), r['views'], r['downloads'], r['denied'],
                      '; '.join(r['people']), r['file'].sha256) for r in rows], 'file_access')
    return render(request, 'reports/file_access.html', {'days': days, 'periods': PERIODS, 'rows': rows})