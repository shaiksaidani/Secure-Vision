"""Access requests: an employee asks for a file they can't open; an
administrator approves (which grants access) or rejects. Everything is
audited and both sides are notified."""
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from notifications.models import Notification
from notifications.services import notify, notify_many, users_with_privilege

from . import access
from .models import AccessRequest, ProtectedFile

Action = AuditLog.Action


@privilege_required(Privilege.REQUEST_FILE_ACCESS)
@require_POST
def request_access_view(request, public_id):
    protected_file = get_object_or_404(ProtectedFile, public_id=public_id)
    back = redirect('vault:viewer', public_id=protected_file.public_id)
    allowed, _reason = access.check_access(request.user, protected_file, access.VIEW)
    if allowed:
        messages.info(request, 'You already have access to this file.')
        return back
    if protected_file.status == ProtectedFile.Status.EXPIRED or protected_file.is_past_expiry:
        messages.error(request, 'This file has expired, so access can no longer be requested.')
        return back
    if AccessRequest.objects.filter(file=protected_file, requester=request.user,
                                    status=AccessRequest.Status.PENDING).exists():
        messages.info(request, 'Your request is already waiting for review.')
        return back
    reason = ' '.join((request.POST.get('reason') or '').split())[:500]
    if len(reason) < 5:
        messages.error(request, 'Please tell the administrator briefly why you need access.')
        return back

    item = AccessRequest.objects.create(file=protected_file, requester=request.user, reason=reason)
    log_event(Action.ACCESS_REQUEST, request=request, target='file:{}'.format(protected_file.public_id),
              details={'request': str(item.public_id), 'title': protected_file.title})
    notify_many(users_with_privilege(Privilege.REVIEW_ALL_ACCESS_REQUESTS), Notification.Kind.REQUEST,
                'New access request requires review',
                '{} asked for access to "{}".'.format(request.user.full_name, protected_file.title),
                url=reverse('vault:requests'), exclude=request.user)
    messages.success(request, 'Request sent. You will be notified when it is reviewed.')
    return back


@privilege_required(Privilege.REVIEW_TEAM_ACCESS_REQUESTS)
def requests_view(request):
    visible = access.requests_visible_to(request.user)
    return render(request, 'vault/requests.html', {
        'pending': visible.filter(status=AccessRequest.Status.PENDING),
        'decided': visible.exclude(status=AccessRequest.Status.PENDING)[:30],
        'can_decide': request.user.has_privilege(Privilege.REVIEW_ALL_ACCESS_REQUESTS),
    })


@privilege_required(Privilege.REVIEW_ALL_ACCESS_REQUESTS)
@require_POST
def decide_view(request, public_id):
    item = get_object_or_404(AccessRequest.objects.select_related('file', 'requester'), public_id=public_id)
    if item.status != AccessRequest.Status.PENDING:
        messages.info(request, 'That request was already {}.'.format(item.get_status_display().lower()))
        return redirect('vault:requests')
    decision = request.POST.get('decision', '')
    note = ' '.join((request.POST.get('note') or '').split())[:255]
    if decision not in ('approve', 'reject'):
        messages.error(request, 'Choose approve or reject.')
        return redirect('vault:requests')

    item.decided_by = request.user
    item.decided_at = timezone.now()
    item.decision_note = note
    file_url = reverse('vault:viewer', args=[item.file.public_id])
    target = 'file:{}'.format(item.file.public_id)
    if decision == 'approve':
        item.status = AccessRequest.Status.APPROVED
        item.save()
        item.file.allowed_users.add(item.requester)      # the actual permission change
        log_event(Action.ACCESS_APPROVED, request=request, target=target,
                  details={'request': str(item.public_id), 'user': item.requester.email,
                           'title': item.file.title, 'note': note})
        notify(item.requester, Notification.Kind.ACCESS,
               'You have been granted access to "{}"'.format(item.file.title), note, url=file_url)
        messages.success(request, '{} can now open "{}".'.format(item.requester.full_name, item.file.title))
    else:
        item.status = AccessRequest.Status.REJECTED
        item.save()
        log_event(Action.ACCESS_REJECTED, request=request, target=target,
                  details={'request': str(item.public_id), 'user': item.requester.email,
                           'title': item.file.title, 'note': note})
        notify(item.requester, Notification.Kind.ACCESS,
               'Your request for "{}" was not approved'.format(item.file.title), note,
               url=reverse('vault:stored_data'))
        messages.success(request, 'Request from {} rejected.'.format(item.requester.full_name))
    return redirect('vault:requests')