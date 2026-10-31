"""DRM Hub (admin upload and permissions) and Stored Data (authorized
viewing). Every byte of a protected file passes through check_access()."""
import uuid

from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_sameorigin

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event

from forensics.models import Watermark
from forensics.services import can_watermark, issue_copy
from forensics.watermark import perceptual_hash
from notifications.models import Notification
from notifications.services import notify_many

from . import access
from .forms import FileEditForm, UploadForm
from .models import AccessRequest, ProtectedFile
from .protection import IntegrityError, delete_blob, read_blob, sha256_hex, write_blob

Action = AuditLog.Action
Result = AuditLog.Result

DENIAL_MESSAGES = {
    access.DENIED_NOT_AUTHORIZED: ('Access restricted',
                                   'You do not have permission to access this file.', 403),
    access.DENIED_EXPIRED: ('File expired',
                            'This file has expired and is no longer available.', 410),
    access.DENIED_NO_DOWNLOAD: ('Download not permitted',
                                'This file can only be viewed in the secure viewer.', 403),
}


def _target(protected_file):
    return 'file:{}'.format(protected_file.public_id)


def _blocked(request, reason, protected_file, action):
    """Audit the denial and show a clear, non-technical message."""
    heading, message, status = DENIAL_MESSAGES[reason]
    log_event(Action.ACCESS_DENIED, request=request, target=_target(protected_file),
              result=Result.DENIED, details={'reason': reason, 'action': action})
    context = {'heading': heading, 'message': message, 'reason': reason}
    if reason == access.DENIED_NOT_AUTHORIZED:
        context.update({
            'file': protected_file,
            'can_request': request.user.has_privilege(Privilege.REQUEST_FILE_ACCESS),
            'last_request': AccessRequest.objects.filter(file=protected_file, requester=request.user).first(),
        })
    return render(request, 'vault/blocked.html', context, status=status)


def _announce_new_access(request, protected_file, before_ids):
    """Notify people who can open the file now but couldn't before."""
    newcomers = access.users_with_access(protected_file).exclude(pk__in=before_ids)
    notify_many(newcomers, Notification.Kind.ACCESS,
                'You have been granted access to "{}"'.format(protected_file.title),
                'Shared by {}.'.format(request.user.full_name),
                url=reverse('vault:viewer', args=[protected_file.public_id]), exclude=request.user)


def _integrity_failure(request, protected_file, error):
    log_event(Action.INTEGRITY_FAILURE, request=request, target=_target(protected_file),
              result=Result.FAILURE, details={'title': protected_file.title, 'error': str(error)})
    return render(request, 'vault/blocked.html', {
        'heading': 'Integrity check failed',
        'message': "This file's stored copy failed its integrity check, so it can't be opened. "
                   'The event has been recorded for administrators.',
        'reason': 'integrity',
    }, status=409)


def _grant_snapshot(protected_file):
    return {
        'teams': sorted(protected_file.allowed_teams.values_list('name', flat=True)),
        'users': sorted(protected_file.allowed_users.values_list('email', flat=True)),
        'allow_download': protected_file.allow_download,
        'visible_watermark': protected_file.visible_watermark,
        'forensic_watermark': protected_file.forensic_watermark,
        'expires_at': protected_file.expires_at.isoformat() if protected_file.expires_at else None,
        'title': protected_file.title,
    }


# --------------------------------------------------------------------------
# Stored Data (everyone with VIEW_AUTHORIZED_FILES)
# --------------------------------------------------------------------------
@privilege_required(Privilege.VIEW_AUTHORIZED_FILES)
def stored_data_view(request):
    access.expire_due_files()
    visible = access.files_visible_to(request.user)
    counts = dict(visible.order_by().values_list('category').annotate(n=Count('id', distinct=True)))
    category = request.GET.get('category', '')
    query = request.GET.get('q', '').strip()
    files = visible.select_related('uploaded_by')
    if category in ProtectedFile.Category.values:
        files = files.filter(category=category)
    if query:
        files = files.filter(title__icontains=query)
    tabs = [{'value': '', 'label': 'All', 'count': sum(counts.values()), 'active': not category}]
    for value, label in ProtectedFile.Category.choices:
        tabs.append({'value': value, 'label': label, 'count': counts.get(value, 0),
                     'active': category == value})
    return render(request, 'vault/stored_data.html', {
        'files': files, 'tabs': tabs, 'category': category, 'query': query,
        'my_requests': AccessRequest.objects.filter(requester=request.user).select_related('file')[:10],
    })


@privilege_required(Privilege.VIEW_AUTHORIZED_FILES)
def file_viewer_view(request, public_id):
    protected_file = get_object_or_404(ProtectedFile.objects.select_related('uploaded_by'),
                                       public_id=public_id)
    allowed, reason = access.check_access(request.user, protected_file, access.VIEW)
    if not allowed:
        return _blocked(request, reason, protected_file, access.VIEW)

    text_content = None
    if protected_file.category == ProtectedFile.Category.TEXT:
        try:
            data = read_blob(protected_file.storage_name, protected_file.sha256)
        except IntegrityError as error:
            return _integrity_failure(request, protected_file, error)
        text_content = data.decode('utf-8-sig', errors='replace')  # shown as plain, escaped text
        log_event(Action.FILE_VIEW, request=request, target=_target(protected_file),
                  details={'title': protected_file.title})

    can_download, _reason = access.check_access(request.user, protected_file, access.DOWNLOAD)
    watermark = '{} | {}'.format(request.user.email, timezone.localtime().strftime('%d %b %Y %H:%M'))
    return render(request, 'vault/viewer.html', {
        'file': protected_file,
        'text_content': text_content,
        'can_download': can_download,
        'can_manage': access.is_file_admin(request.user),
        'watermark_text': watermark,
        'watermark_repeat': range(24),
        'forensic_copy': can_watermark(protected_file),
    })


@xframe_options_sameorigin  # lets the viewer page embed PDFs; other sites still can't frame it
@privilege_required(Privilege.VIEW_AUTHORIZED_FILES)
def file_content_view(request, public_id):
    protected_file = get_object_or_404(ProtectedFile, public_id=public_id)
    allowed, reason = access.check_access(request.user, protected_file, access.VIEW)
    if not allowed:
        return _blocked(request, reason, protected_file, access.VIEW)
    try:
        data = read_blob(protected_file.storage_name, protected_file.sha256)
    except IntegrityError as error:
        return _integrity_failure(request, protected_file, error)
    data, mime_type, _name, mark = issue_copy(request, protected_file, data, Watermark.Purpose.VIEW)
    log_event(Action.FILE_VIEW, request=request, target=_target(protected_file),
              details={'title': protected_file.title, 'watermark': mark.code if mark else None})
    response = HttpResponse(data, content_type=mime_type)
    response['Content-Disposition'] = 'inline'
    response['Cache-Control'] = 'no-store, private'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@privilege_required(Privilege.VIEW_AUTHORIZED_FILES)
def file_download_view(request, public_id):
    protected_file = get_object_or_404(ProtectedFile, public_id=public_id)
    allowed, reason = access.check_access(request.user, protected_file, access.DOWNLOAD)
    if not allowed:
        return _blocked(request, reason, protected_file, access.DOWNLOAD)
    try:
        data = read_blob(protected_file.storage_name, protected_file.sha256)
    except IntegrityError as error:
        return _integrity_failure(request, protected_file, error)
    data, mime_type, file_name, mark = issue_copy(request, protected_file, data, Watermark.Purpose.DOWNLOAD)
    log_event(Action.FILE_DOWNLOAD, request=request, target=_target(protected_file),
              details={'title': protected_file.title, 'sha256': sha256_hex(data),
                       'watermark': mark.code if mark else None})
    response = HttpResponse(data, content_type=mime_type)
    safe_name = file_name.replace('"', '').replace('\r', '').replace('\n', '')
    response['Content-Disposition'] = 'attachment; filename="{}"'.format(safe_name)
    response['Cache-Control'] = 'no-store, private'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


# --------------------------------------------------------------------------
# DRM Hub (admin only)
# --------------------------------------------------------------------------
@privilege_required(Privilege.UPLOAD_PROTECTED_FILES)
def drm_hub_view(request):
    access.expire_due_files()
    form = UploadForm(request.POST or None, request.FILES or None)
    if request.method == 'POST' and form.is_valid():
        safe_name, ext, category, mime = form.file_info
        data = form.file_bytes
        storage_name = uuid.uuid4().hex
        write_blob(storage_name, data)  # encrypted copy of the ORIGINAL bytes
        try:
            with transaction.atomic():
                protected_file = form.save(commit=False)
                protected_file.title = form.cleaned_data.get('title') or safe_name
                protected_file.original_filename = safe_name
                protected_file.extension = ext
                protected_file.category = category
                protected_file.mime_type = mime
                protected_file.size_bytes = len(data)
                protected_file.sha256 = sha256_hex(data)
                protected_file.storage_name = storage_name
                protected_file.uploaded_by = request.user
                if category == ProtectedFile.Category.IMAGE:
                    protected_file.perceptual_hash = perceptual_hash(data)
                protected_file.save()
                form.save_m2m()
        except Exception:
            delete_blob(storage_name)
            raise
        details = _grant_snapshot(protected_file)
        details.update({'size': protected_file.size_bytes, 'sha256': protected_file.sha256})
        log_event(Action.FILE_UPLOAD, request=request, target=_target(protected_file), details=details)
        _announce_new_access(request, protected_file, before_ids=[])
        messages.success(request, '"{}" uploaded and encrypted.'.format(protected_file.title))
        return redirect('vault:hub')

    files = (ProtectedFile.objects.select_related('uploaded_by')
             .prefetch_related('allowed_teams', 'allowed_users'))
    expiring = [f for f in files if f.status == ProtectedFile.Status.ACTIVE and f.expires_soon]
    return render(request, 'vault/hub.html', {
        'form': form,
        'files': files,
        'expiring': expiring,
        'max_mb': settings.SV_MAX_UPLOAD_MB,
    })


@privilege_required(Privilege.MANAGE_FILE_PERMISSIONS)
def file_edit_view(request, public_id):
    protected_file = get_object_or_404(ProtectedFile, public_id=public_id)
    before = _grant_snapshot(protected_file)
    title_before = protected_file.title
    had_access = list(access.users_with_access(protected_file).values_list('pk', flat=True))
    form = FileEditForm(request.POST or None, instance=protected_file)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            protected_file = form.save()
            # A new future expiry re-opens an expired file.
            if (protected_file.status == ProtectedFile.Status.EXPIRED
                    and not protected_file.is_past_expiry):
                protected_file.status = ProtectedFile.Status.ACTIVE
                protected_file.save(update_fields=['status', 'updated_at'])
        after = _grant_snapshot(protected_file)
        changes = {key: [before[key], after[key]] for key in before if before[key] != after[key]}
        if changes:
            log_event(Action.PERMISSION_CHANGED, request=request, target=_target(protected_file),
                      details=changes)
            _announce_new_access(request, protected_file, before_ids=had_access)
            messages.success(request, 'Access settings for "{}" updated.'.format(protected_file.title))
        else:
            messages.info(request, 'No changes to save.')
        return redirect('vault:hub')
    return render(request, 'vault/file_form.html', {
        'form': form, 'file': protected_file, 'title_before': title_before,
    })