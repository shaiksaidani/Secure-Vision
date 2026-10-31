"""The ONE place that decides who may open or download a protected file.
Every view calls these functions; templates never decide access."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from notifications.models import Notification
from notifications.services import notify
from teams.models import TeamMembership

from .models import AccessRequest, ProtectedFile

User = get_user_model()

VIEW = 'view'
DOWNLOAD = 'download'

DENIED_NOT_AUTHORIZED = 'not_authorized'
DENIED_EXPIRED = 'expired'
DENIED_NO_DOWNLOAD = 'download_not_allowed'


def is_file_admin(user):
    return user.has_privilege(Privilege.MANAGE_FILE_PERMISSIONS)


def expire_due_files():
    """Mark files past their expiry as EXPIRED and record each one once."""
    due = ProtectedFile.objects.filter(status=ProtectedFile.Status.ACTIVE,
                                       expires_at__isnull=False,
                                       expires_at__lte=timezone.now())
    for item in due:
        updated = ProtectedFile.objects.filter(
            pk=item.pk, status=ProtectedFile.Status.ACTIVE).update(
            status=ProtectedFile.Status.EXPIRED)
        if updated:
            log_event(AuditLog.Action.FILE_EXPIRED, actor_label='system',
                      target='file:{}'.format(item.public_id), result=AuditLog.Result.INFO,
                      details={'title': item.title, 'expired_at': item.expires_at})
    remind_expiring_files()


def users_with_access(protected_file):
    """Active people who can open the file through a direct grant or a team."""
    team_ids = protected_file.allowed_teams.values('pk')
    return User.objects.filter(is_active=True).filter(
        Q(granted_files=protected_file) | Q(team_memberships__team__in=team_ids)).distinct()


def remind_expiring_files():
    """Tell everyone with access, once, when a file expires within 24 hours."""
    now = timezone.now()
    for item in ProtectedFile.objects.filter(status=ProtectedFile.Status.ACTIVE,
                                             expires_at__gt=now, expires_at__lte=now + timedelta(hours=24)):
        when = timezone.localtime(item.expires_at).strftime('%d %b %Y, %I:%M %p')
        for person in users_with_access(item):
            notify(person, Notification.Kind.EXPIRY, '"{}" expires within 24 hours'.format(item.title),
                   'It will no longer be available after {}.'.format(when),
                   url=reverse('vault:viewer', args=[item.public_id]),
                   object_ref='file:{}'.format(item.public_id), once=True)


def requests_visible_to(user):
    """Admins see every request; Team Leaders see requests from their team members."""
    requests = AccessRequest.objects.select_related('file', 'requester', 'decided_by')
    if user.has_privilege(Privilege.REVIEW_ALL_ACCESS_REQUESTS):
        return requests
    if user.has_privilege(Privilege.REVIEW_TEAM_ACCESS_REQUESTS):
        return requests.filter(requester__team_memberships__team__leader=user).distinct()
    return requests.none()


def files_visible_to(user):
    """Files the user may see in Stored Data."""
    files = ProtectedFile.objects.all()
    if is_file_admin(user):
        return files
    if not user.has_privilege(Privilege.VIEW_AUTHORIZED_FILES):
        return files.none()
    my_teams = TeamMembership.objects.filter(user=user).values('team_id')
    return files.filter(Q(allowed_users=user) | Q(allowed_teams__in=my_teams)).distinct()


def check_access(user, protected_file, action=VIEW):
    """Return (allowed, reason). Reason is one of the DENIED_* constants."""
    if not files_visible_to(user).filter(pk=protected_file.pk).exists():
        return False, DENIED_NOT_AUTHORIZED
    if protected_file.is_past_expiry or protected_file.status == ProtectedFile.Status.EXPIRED:
        expire_due_files()
        return False, DENIED_EXPIRED
    if action == DOWNLOAD and not (protected_file.allow_download or is_file_admin(user)):
        return False, DENIED_NO_DOWNLOAD
    return True, None