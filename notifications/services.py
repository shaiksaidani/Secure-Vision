"""The single way every module notifies people."""
import logging

from django.contrib.auth import get_user_model

from accounts.permissions import ROLE_PRIVILEGES

from .models import Notification

logger = logging.getLogger('securevision.notifications')
User = get_user_model()


def notify(user, kind, title, body='', url='', object_ref='', once=False):
    """Create a notification. With once=True and an object_ref, the same
    user never gets the same kind of notification for that object twice."""
    if user is None or not user.is_active:
        return None
    if once and object_ref and Notification.objects.filter(
            user=user, kind=kind, object_ref=object_ref).exists():
        return None
    try:
        return Notification.objects.create(user=user, kind=kind, title=title[:200], body=body[:500],
                                           url=url[:300], object_ref=object_ref[:100])
    except Exception:  # a notification must never break the action that caused it
        logger.exception('Could not create notification for %s', user.pk)
        return None


def notify_many(users, kind, title, body='', url='', object_ref='', once=False, exclude=None):
    sent = 0
    for user in users:
        if exclude is not None and user.pk == exclude.pk:
            continue
        if notify(user, kind, title, body, url, object_ref, once):
            sent += 1
    return sent


def users_with_privilege(privilege):
    roles = [role for role, privileges in ROLE_PRIVILEGES.items() if privilege in privileges]
    return User.objects.filter(is_active=True, role__in=roles)


def unread_count(user):
    return Notification.objects.filter(user=user, read_at__isnull=True).count()