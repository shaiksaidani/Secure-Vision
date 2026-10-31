"""User Management (admin only): search users, assign roles, deactivate and
reactivate accounts. Every change is enforced server-side and audited."""
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from audit.models import AuditLog
from audit.services import log_event

from .decorators import privilege_required
from .models import UserSession
from .permissions import ROLE_DESCRIPTIONS, Privilege
from .sessions import end_user_sessions
from .utils import safe_next_url

User = get_user_model()
Action = AuditLog.Action


def _back(request):
    return safe_next_url(request) or reverse('accounts:user_list')


def _active_admin_count():
    return User.objects.filter(role=User.Role.ADMIN, is_active=True).count()


@privilege_required(Privilege.MANAGE_USERS)
def user_list_view(request):
    query = request.GET.get('q', '').strip()
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')

    users = User.objects.all().order_by('full_name', 'email')
    if query:
        users = users.filter(Q(full_name__icontains=query) | Q(email__icontains=query)
                             | Q(username__icontains=query))
    if role_filter in User.Role.values:
        users = users.filter(role=role_filter)
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)

    everyone = User.objects.all()
    counts = {
        'total': everyone.count(),
        'active': everyone.filter(is_active=True).count(),
        'admins': everyone.filter(role=User.Role.ADMIN).count(),
        'leaders': everyone.filter(role=User.Role.TEAM_LEADER).count(),
        'employees': everyone.filter(role=User.Role.EMPLOYEE).count(),
    }
    return render(request, 'accounts/user_list.html', {
        'users': users[:200],
        'query': query,
        'role_filter': role_filter,
        'status_filter': status_filter,
        'role_choices': User.Role.choices,
        'role_descriptions': [(value, label, ROLE_DESCRIPTIONS.get(value, ''))
                              for value, label in User.Role.choices],
        'counts': counts,
        'current_url': request.get_full_path(),
    })


@privilege_required(Privilege.MANAGE_USERS)
@require_POST
def user_set_role_view(request, pk):
    target = get_object_or_404(User, pk=pk)
    new_role = request.POST.get('role', '')

    if new_role not in User.Role.values:
        messages.error(request, 'Please choose a valid role.')
    elif target.pk == request.user.pk:
        messages.error(request, "You can't change your own role. Ask another administrator.")
    elif new_role == target.role:
        messages.info(request, '{} is already {}.'.format(target.full_name, target.get_role_display()))
    elif (target.role == User.Role.ADMIN and target.is_active
          and _active_admin_count() <= 1):
        messages.error(request, 'SecureVision needs at least one active administrator.')
    else:
        old_label = target.get_role_display()
        old_role = target.role
        target.role = new_role
        target.save(update_fields=['role'])
        log_event(Action.PERMISSION_CHANGED, request=request,
                  target='user:{}'.format(target.pk),
                  details={'user': target.email, 'old_role': old_role, 'new_role': new_role})
        messages.success(request, "{}'s role changed from {} to {}.".format(
            target.full_name, old_label, target.get_role_display()))
    return redirect(_back(request))


@privilege_required(Privilege.MANAGE_USERS)
@require_POST
def user_set_status_view(request, pk):
    target = get_object_or_404(User, pk=pk)
    action = request.POST.get('action', '')

    if target.pk == request.user.pk:
        messages.error(request, "You can't deactivate your own account.")
    elif action == 'deactivate':
        if not target.is_active:
            messages.info(request, '{} is already deactivated.'.format(target.full_name))
        elif target.role == User.Role.ADMIN and _active_admin_count() <= 1:
            messages.error(request, 'SecureVision needs at least one active administrator.')
        else:
            target.is_active = False
            target.save(update_fields=['is_active'])
            ended = end_user_sessions(target, UserSession.EndReason.DEACTIVATED)
            log_event(Action.USER_REMOVED, request=request,
                      target='user:{}'.format(target.pk),
                      details={'user': target.email, 'sessions_ended': ended})
            messages.success(request, '{} has been deactivated and signed out everywhere.'.format(
                target.full_name))
    elif action == 'activate':
        if target.is_active:
            messages.info(request, '{} is already active.'.format(target.full_name))
        else:
            target.is_active = True
            target.save(update_fields=['is_active'])
            log_event(Action.USER_REACTIVATED, request=request,
                      target='user:{}'.format(target.pk), details={'user': target.email})
            messages.success(request, '{} has been reactivated.'.format(target.full_name))
    else:
        messages.error(request, 'Unknown action.')
    return redirect(_back(request))