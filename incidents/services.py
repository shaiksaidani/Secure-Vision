"""Opening and working incidents, and adding / verifying evidence."""
import json
import uuid
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from accounts.utils import describe_user_agent
from audit.models import AuditLog
from audit.services import get_client_ip, get_user_agent, log_event
from notifications.models import Notification
from notifications.services import notify
from security.models import SecurityAlert
from vault.protection import IntegrityError, read_blob, sha256_hex, write_blob

from .models import CustodyRecord, Evidence, Incident, IncidentEntry

Action = AuditLog.Action


def _next_reference():
    prefix = 'INC-{}-'.format(timezone.localdate().year)
    last = (Incident.objects.filter(reference__startswith=prefix).order_by('-reference')
            .values_list('reference', flat=True).first())
    number = int(last.rsplit('-', 1)[1]) + 1 if last else 1
    return '{}{:04d}'.format(prefix, number)


def add_entry(incident, kind, author, text):
    entry = IncidentEntry.objects.create(incident=incident, kind=kind, author=author, text=text[:4000])
    Incident.objects.filter(pk=incident.pk).update(updated_at=timezone.now())
    return entry


def _custody(request, evidence, action, sha256_observed='', note=''):
    return CustodyRecord.objects.create(
        evidence=evidence, action=action, actor=request.user, actor_label=request.user.email,
        ip_address=get_client_ip(request), device=describe_user_agent(get_user_agent(request)),
        sha256_observed=sha256_observed, note=note[:255])


def _notify_assignee(incident, actor, text):
    if incident.assigned_to and incident.assigned_to != actor:
        notify(incident.assigned_to, Notification.Kind.SECURITY, '{}: {}'.format(incident.reference, text),
               incident.title, url=reverse('incidents:detail', args=[incident.public_id]))


@transaction.atomic
def open_incident(request, title, summary, severity, assigned_to=None, subject_user=None,
                  related_file=None, alert=None, analysis=None):
    incident = Incident.objects.create(
        reference=_next_reference(), title=title, summary=summary, severity=severity,
        created_by=request.user, assigned_to=assigned_to, subject_user=subject_user, related_file=related_file)
    add_entry(incident, IncidentEntry.Kind.CREATED, request.user, 'Incident opened by {}.'.format(
        request.user.full_name))
    if alert is not None:
        link_alert(request, incident, alert)
    if analysis is not None:
        link_analysis(request, incident, analysis)
    log_event(Action.INCIDENT_CREATED, request=request, target='incident:{}'.format(incident.reference),
              details={'title': title, 'severity': severity,
                       'alert': str(alert.public_id) if alert else None,
                       'analysis': str(analysis.public_id) if analysis else None})
    _notify_assignee(incident, request.user, 'assigned to you')
    return incident


def link_alert(request, incident, alert):
    incident.alerts.add(alert)
    if alert.status == SecurityAlert.Status.OPEN:
        SecurityAlert.objects.filter(pk=alert.pk).update(
            status=SecurityAlert.Status.ACKNOWLEDGED, handled_by=request.user, handled_at=timezone.now())
    add_entry(incident, IncidentEntry.Kind.LINKED, request.user,
              'Linked security alert "{}" ({}).'.format(alert.title, alert.get_severity_display()))


def link_analysis(request, incident, analysis):
    incident.analyses.add(analysis)
    add_entry(incident, IncidentEntry.Kind.LINKED, request.user,
              'Linked forensic analysis of "{}" (risk {}).'.format(analysis.sample_name, analysis.get_risk_display()))
    if analysis.sample_storage and not incident.evidence.filter(
            source_ref='analysis:{}'.format(analysis.public_id)).exists():
        try:
            data = read_blob(analysis.sample_storage, analysis.sample_sha256)
        except IntegrityError:
            add_entry(incident, IncidentEntry.Kind.NOTE, request.user,
                      'The stored forensic sample could not be read, so it was not added as evidence.')
            return
        add_evidence(request, incident, Evidence.Kind.FORENSIC_SAMPLE,
                     'Forensic sample: {}'.format(analysis.sample_name),
                     'Sample analysed on {}. Risk {}.'.format(
                         timezone.localtime(analysis.created_at).strftime('%d %b %Y, %I:%M %p'),
                         analysis.get_risk_display()),
                     analysis.sample_name, 'application/octet-stream', data,
                     source_ref='analysis:{}'.format(analysis.public_id))


def update_incident(request, incident, status, severity, assigned_to, note):
    changes = []
    if status != incident.status:
        changes.append((IncidentEntry.Kind.STATUS, 'Status: {} -> {}.'.format(
            incident.get_status_display(), Incident.Status(status).label)))
        incident.status = status
        incident.closed_at = timezone.now() if status in (Incident.Status.RESOLVED, Incident.Status.CLOSED) else None
    if severity != incident.severity:
        changes.append((IncidentEntry.Kind.SEVERITY, 'Severity: {} -> {}.'.format(
            incident.get_severity_display(), Incident.Severity(severity).label)))
        incident.severity = severity
    if assigned_to != incident.assigned_to:
        changes.append((IncidentEntry.Kind.ASSIGNED, 'Assigned to {}.'.format(
            assigned_to.full_name if assigned_to else 'nobody')))
        incident.assigned_to = assigned_to
    if not changes and not note:
        return False
    incident.save()
    for kind, text in changes:
        add_entry(incident, kind, request.user, text)
    if note:
        add_entry(incident, IncidentEntry.Kind.NOTE, request.user, note)
    log_event(Action.INCIDENT_UPDATED, request=request, target='incident:{}'.format(incident.reference),
              details={'changes': [text for _kind, text in changes], 'note': bool(note)})
    if any(kind == IncidentEntry.Kind.ASSIGNED for kind, _t in changes):
        _notify_assignee(incident, request.user, 'assigned to you')
    return True


def add_evidence(request, incident, kind, title, description, filename, mime_type, data, source_ref=''):
    number = incident.evidence.count() + 1
    storage_name = 'ev-' + uuid.uuid4().hex
    write_blob(storage_name, data)                    # encrypted at rest
    evidence = Evidence.objects.create(
        reference='{}-E{:02d}'.format(incident.reference, number), incident=incident, kind=kind,
        title=title[:200], description=description[:2000], original_filename=filename[:255],
        mime_type=mime_type[:100] or 'application/octet-stream', size_bytes=len(data),
        sha256=sha256_hex(data), storage_name=storage_name, source_ref=source_ref[:100], added_by=request.user)
    _custody(request, evidence, CustodyRecord.Action.ADDED, evidence.sha256)
    add_entry(incident, IncidentEntry.Kind.EVIDENCE, request.user,
              'Evidence {} added: {} (SHA-256 {}).'.format(evidence.reference, evidence.title, evidence.sha256))
    log_event(Action.EVIDENCE_ADDED, request=request, target='evidence:{}'.format(evidence.reference),
              details={'incident': incident.reference, 'title': evidence.title, 'kind': kind,
                       'sha256': evidence.sha256, 'size': evidence.size_bytes})
    return evidence


def add_activity_snapshot(request, incident, days=30):
    """Freeze the relevant audit events into a JSON evidence item."""
    since = timezone.now() - timedelta(days=days)
    scope = Q(pk__in=[])
    if incident.subject_user_id:
        scope |= Q(user_id=incident.subject_user_id)
    if incident.related_file_id:
        scope |= Q(target='file:{}'.format(incident.related_file.public_id))
    for alert in incident.alerts.all():
        if alert.user_id:
            scope |= Q(user_id=alert.user_id)
        if alert.target:
            scope |= Q(target=alert.target)
    events = AuditLog.objects.filter(scope, timestamp__gte=since).order_by('timestamp')[:5000]
    rows = [{
        'event_id': str(e.event_id), 'time': e.timestamp.isoformat(), 'account': e.actor_label,
        'action': e.action, 'target': e.target, 'result': e.result, 'ip': e.ip_address,
        'device': describe_user_agent(e.user_agent) if e.user_agent else '', 'session': e.session_ref,
        'details': e.details_dict,
    } for e in events]
    payload = json.dumps({'incident': incident.reference, 'generated_at': timezone.now().isoformat(),
                          'generated_by': request.user.email, 'period_days': days, 'events': rows},
                         indent=2, default=str).encode('utf-8')
    return add_evidence(request, incident, Evidence.Kind.ACTIVITY_SNAPSHOT,
                        'Activity log snapshot ({} events, last {} days)'.format(len(rows), days),
                        'Audit events for the people, files and alerts linked to this incident.',
                        'activity-{}.json'.format(incident.reference), 'application/json', payload)


def read_evidence(request, evidence, action):
    """Decrypt evidence for download or verification. Returns bytes or None
    (if the stored copy is missing or altered). Always recorded."""
    try:
        data = read_blob(evidence.storage_name, evidence.sha256)
    except IntegrityError as error:
        _custody(request, evidence, CustodyRecord.Action.VERIFY_FAILED, note=str(error))
        log_event(Action.EVIDENCE_VERIFIED, request=request, target='evidence:{}'.format(evidence.reference),
                  result=AuditLog.Result.FAILURE, details={'error': str(error)})
        return None
    custody_action = CustodyRecord.Action.DOWNLOADED if action == 'download' else CustodyRecord.Action.VERIFIED
    _custody(request, evidence, custody_action, sha256_hex(data))
    log_event(Action.EVIDENCE_ACCESSED if action == 'download' else Action.EVIDENCE_VERIFIED,
              request=request, target='evidence:{}'.format(evidence.reference),
              details={'sha256': evidence.sha256, 'incident': evidence.incident.reference})
    return data