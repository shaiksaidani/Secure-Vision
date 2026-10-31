"""Incident Management and the Evidence Vault (administrators)."""
from django.contrib import messages
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from forensics.models import ForensicAnalysis
from security.models import SecurityAlert

from . import services
from .forms import EvidenceUploadForm, IncidentForm, IncidentUpdateForm
from .models import Evidence, Incident

MANAGE = Privilege.MANAGE_INCIDENTS


def _incident_or_404(public_id):
    return get_object_or_404(Incident.objects.select_related(
        'created_by', 'assigned_to', 'subject_user', 'related_file'), public_id=public_id)


@privilege_required(MANAGE)
def incident_list_view(request):
    status = request.GET.get('status', 'active')
    severity = request.GET.get('severity', '')
    query = request.GET.get('q', '').strip()
    incidents = Incident.objects.select_related('assigned_to', 'subject_user').annotate(
        evidence_count=Count('evidence', distinct=True))
    if status == 'active':
        incidents = incidents.filter(status__in=Incident.ACTIVE_STATUSES)
    elif status in Incident.Status.values:
        incidents = incidents.filter(status=status)
    if severity in Incident.Severity.values:
        incidents = incidents.filter(severity=severity)
    if query:
        incidents = incidents.filter(Q(reference__icontains=query) | Q(title__icontains=query)
                                     | Q(subject_user__full_name__icontains=query))
    counts = dict(Incident.objects.values_list('status').annotate(n=Count('id')))
    return render(request, 'incidents/list.html', {
        'incidents': incidents, 'status': status, 'severity': severity, 'query': query,
        'statuses': Incident.Status.choices, 'severities': Incident.Severity.choices,
        'counts': counts, 'active_count': sum(counts.get(s, 0) for s in Incident.ACTIVE_STATUSES),
    })


@privilege_required(MANAGE)
def incident_create_view(request):
    alert = analysis = None
    alert_id = request.GET.get('alert') or request.POST.get('alert')
    analysis_id = request.GET.get('analysis') or request.POST.get('analysis')
    try:
        if alert_id:
            alert = SecurityAlert.objects.filter(public_id=alert_id).select_related('user').first()
        if analysis_id:
            analysis = (ForensicAnalysis.objects.filter(public_id=analysis_id)
                        .select_related('associated_user', 'matched_file').first())
    except Exception:  # a malformed id in the address bar
        alert = analysis = None

    initial = {'assigned_to': request.user}
    if alert:
        initial.update({'title': alert.title, 'summary': alert.description, 'subject_user': alert.user,
                        'severity': alert.severity})
    elif analysis:
        initial.update({'title': 'Possible leak: {}'.format(analysis.sample_name), 'summary': analysis.summary,
                        'subject_user': analysis.associated_user, 'related_file': analysis.matched_file,
                        'severity': {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM'}.get(analysis.risk, 'LOW')})
    form = IncidentForm(request.POST or None, initial=initial)
    if request.method == 'POST' and form.is_valid():
        data = form.cleaned_data
        incident = services.open_incident(
            request, data['title'], data['summary'], data['severity'], assigned_to=data['assigned_to'],
            subject_user=data['subject_user'], related_file=data['related_file'], alert=alert, analysis=analysis)
        messages.success(request, 'Incident {} opened.'.format(incident.reference))
        return redirect('incidents:detail', public_id=incident.public_id)
    return render(request, 'incidents/form.html', {'form': form, 'alert': alert, 'analysis': analysis})


@privilege_required(MANAGE)
def incident_detail_view(request, public_id):
    incident = _incident_or_404(public_id)
    update_form = IncidentUpdateForm(initial={
        'status': incident.status, 'severity': incident.severity, 'assigned_to': incident.assigned_to})
    linked_analysis_ids = incident.analyses.values_list('pk', flat=True)
    return render(request, 'incidents/detail.html', {
        'incident': incident,
        'entries': incident.entries.select_related('author'),
        'evidence': incident.evidence.select_related('added_by').annotate(custody_count=Count('custody')),
        'alerts': incident.alerts.select_related('user'),
        'analyses': incident.analyses.select_related('associated_user'),
        'update_form': update_form,
        'upload_form': EvidenceUploadForm(),
        'available_analyses': ForensicAnalysis.objects.exclude(pk__in=linked_analysis_ids)[:20],
    })


@privilege_required(MANAGE)
@require_POST
def incident_update_view(request, public_id):
    incident = _incident_or_404(public_id)
    form = IncidentUpdateForm(request.POST)
    if form.is_valid():
        data = form.cleaned_data
        changed = services.update_incident(request, incident, data['status'], data['severity'],
                                           data['assigned_to'], data['note'].strip())
        if changed:
            messages.success(request, 'Incident updated.')
        else:
            messages.info(request, 'Nothing changed.')
    else:
        messages.error(request, 'Please check the update form.')
    return redirect('incidents:detail', public_id=incident.public_id)


@privilege_required(MANAGE)
@require_POST
def evidence_upload_view(request, public_id):
    incident = _incident_or_404(public_id)
    form = EvidenceUploadForm(request.POST, request.FILES)
    if form.is_valid():
        evidence = services.add_evidence(
            request, incident, Evidence.Kind.UPLOAD, form.cleaned_data['title'] or form.file_name,
            form.cleaned_data['description'], form.file_name, form.file_mime, form.file_bytes)
        messages.success(request, 'Evidence {} added and encrypted.'.format(evidence.reference))
    else:
        for errors in form.errors.values():
            for error in errors:
                messages.error(request, error)
    return redirect('incidents:detail', public_id=incident.public_id)


@privilege_required(MANAGE)
@require_POST
def evidence_snapshot_view(request, public_id):
    incident = _incident_or_404(public_id)
    evidence = services.add_activity_snapshot(request, incident)
    messages.success(request, 'Activity snapshot saved as evidence {}.'.format(evidence.reference))
    return redirect('incidents:detail', public_id=incident.public_id)


@privilege_required(MANAGE)
@require_POST
def link_analysis_view(request, public_id):
    incident = _incident_or_404(public_id)
    analysis_id = request.POST.get('analysis', '')
    analysis = None
    try:
        analysis = ForensicAnalysis.objects.filter(public_id=analysis_id).first() if analysis_id else None
    except Exception:  # not a valid UUID
        analysis = None
    if analysis is None:
        messages.error(request, 'Choose an analysis to link.')
    elif incident.analyses.filter(pk=analysis.pk).exists():
        messages.info(request, 'That analysis is already linked.')
    else:
        services.link_analysis(request, incident, analysis)
        messages.success(request, 'Analysis linked; its sample was added to the Evidence Vault.')
    return redirect('incidents:detail', public_id=incident.public_id)


@privilege_required(MANAGE)
def evidence_detail_view(request, public_id):
    evidence = get_object_or_404(Evidence.objects.select_related('incident', 'added_by'), public_id=public_id)
    return render(request, 'incidents/evidence.html', {
        'evidence': evidence, 'custody': evidence.custody.select_related('actor'),
    })


@privilege_required(MANAGE)
@require_POST
def evidence_verify_view(request, public_id):
    evidence = get_object_or_404(Evidence.objects.select_related('incident'), public_id=public_id)
    if services.read_evidence(request, evidence, 'verify') is None:
        messages.error(request, 'Integrity check FAILED: the stored copy is missing or has been altered. '
                                'This has been recorded.')
    else:
        messages.success(request, 'Integrity verified: the stored copy matches SHA-256 {}.'.format(evidence.sha256))
    return redirect('incidents:evidence', public_id=evidence.public_id)


@privilege_required(MANAGE)
def evidence_download_view(request, public_id):
    evidence = get_object_or_404(Evidence.objects.select_related('incident'), public_id=public_id)
    data = services.read_evidence(request, evidence, 'download')
    if data is None:
        messages.error(request, 'This evidence failed its integrity check and cannot be downloaded.')
        return redirect('incidents:evidence', public_id=evidence.public_id)
    response = HttpResponse(data, content_type='application/octet-stream')
    name = '{}_{}'.format(evidence.reference, evidence.original_filename)
    response['Content-Disposition'] = 'attachment; filename="{}"'.format(
        name.replace('"', '').replace('\r', '').replace('\n', ''))
    response['Cache-Control'] = 'no-store, private'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@privilege_required(MANAGE)
def incident_report_view(request, public_id):
    """Printable incident report (use the browser's Print / Save as PDF)."""
    incident = _incident_or_404(public_id)
    log_event(AuditLog.Action.REPORT_GENERATED, request=request,
              target='incident:{}'.format(incident.reference), details={'report': 'incident'})
    return render(request, 'incidents/report.html', {
        'incident': incident,
        'entries': incident.entries.select_related('author'),
        'evidence': incident.evidence.prefetch_related('custody__actor'),
        'alerts': incident.alerts.all(),
        'analyses': incident.analyses.all(),
        'generated_by': request.user,
    })