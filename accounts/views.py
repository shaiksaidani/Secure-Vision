from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST

from audit.models import AuditLog
from audit.services import log_event
from security.lockout import lock_status
from . import devices
from .forms import (UNKNOWN_EMAIL_MESSAGE, LoginForm, SignupForm,
                    SVPasswordChangeForm, SVPasswordResetForm, SVSetPasswordForm)
from .models import Device, DevicePolicy, UserSession
from .permissions import ROLE_DESCRIPTIONS, privilege_rows
from .sessions import active_sessions_for, end_user_sessions
from .utils import safe_next_url
from .validators import normalize_email

User = get_user_model()
Action = AuditLog.Action
Result = AuditLog.Result


# --------------------------------------------------------------------------
# Sign up
# --------------------------------------------------------------------------
@sensitive_post_parameters('password1', 'password2', 'role_code')
@csrf_protect
@never_cache
def signup_view(request):
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    form = SignupForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        try:
            with transaction.atomic():
                user = form.save()
        except IntegrityError:
            # Two sign-ups racing for the same email/username.
            form.add_error(None, 'An account with this email or username already exists.')
        else:
            log_event(Action.SIGNUP, request=request, user=user,
                      target='user:{}'.format(user.pk), details={'role': user.role})
            messages.success(request, 'Account created for {} as {}. Sign in to continue.'.format(
                user.email, user.get_role_display()))
            return redirect('accounts:login')
    elif request.method == 'POST' and form.role_code_rejected:
        # Wrong authorization code for a privileged role: record the attempt.
        log_event(Action.ACCESS_DENIED, request=request,
                  actor_label=normalize_email(request.POST.get('email', ''))[:254],
                  target='signup:role:{}'.format(form.role_code_rejected),
                  result=Result.DENIED, details={'reason': 'wrong_role_code'})
    return render(request, 'accounts/signup.html', {'form': form})


# --------------------------------------------------------------------------
# Sign in: real database lookup -> password check -> server-side session
# --------------------------------------------------------------------------
def _lock_if_needed(request, form, email, user):
    """After a failed attempt: if that was one too many, lock and record it."""
    locked, minutes = lock_status(email)
    if locked:
        log_event(Action.ACCOUNT_LOCKED, request=request, user=user, actor_label=email,
                  result=Result.DENIED, details={'minutes': minutes})
        form.add_error(None, 'Too many failed sign-in attempts. Try again in {} minute{}.'.format(
            minutes, '' if minutes == 1 else 's'))


@sensitive_post_parameters('password')
@csrf_protect
@never_cache
def login_view(request):
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    reveal = getattr(settings, 'SV_REVEAL_UNKNOWN_EMAIL', True)
    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        user = User.objects.filter(email__iexact=email).first()
        locked, minutes = lock_status(email)

        if locked:
            # Refused before the password is even checked, so guessing is pointless.
            log_event(Action.FAILED_LOGIN, request=request, user=user, actor_label=email,
                      result=Result.DENIED, details={'reason': 'locked'})
            form.add_error(None, 'Too many failed sign-in attempts. Try again in {} minute{}.'.format(
                minutes, '' if minutes == 1 else 's'))
        elif user is None:
            log_event(Action.FAILED_LOGIN, request=request, actor_label=email,
                      result=Result.FAILURE, details={'reason': 'unknown_email'})
            if reveal:
                form.add_error('email', UNKNOWN_EMAIL_MESSAGE)
            else:
                form.add_error(None, 'Incorrect email or password.')
            _lock_if_needed(request, form, email, user)
        elif not user.check_password(password):
            log_event(Action.FAILED_LOGIN, request=request, user=user,
                      result=Result.FAILURE, details={'reason': 'wrong_password'})
            if reveal:
                form.add_error('password', 'Incorrect password.')
            else:
                form.add_error(None, 'Incorrect email or password.')
            _lock_if_needed(request, form, email, user)
        elif not user.is_active:
            log_event(Action.FAILED_LOGIN, request=request, user=user,
                      result=Result.DENIED, details={'reason': 'inactive_account'})
            form.add_error(None, 'This account has been deactivated. Contact your administrator.')
        else:
            try:
                device, token, created = devices.resolve_device(request, user)
            except devices.DeviceBlocked as blocked:
                log_event(Action.DEVICE_BLOCKED, request=request, user=user,
                          result=Result.DENIED, details={'reason': blocked.reason})
                form.add_error(None, str(blocked))
            else:
                # Stores the real user ID in the server-side session. Every later
                # request resolves request.user from the database via this ID,
                # so a page refresh can never turn the user into someone else.
                auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                devices.bind_session(request, device)
                if created:
                    log_event(Action.DEVICE_REGISTERED, request=request, user=user,
                              target='device:{}'.format(device.public_id),
                              details={'device': device.name, 'kind': device.kind})
                response = redirect(safe_next_url(request) or 'core:dashboard')
                return devices.set_cookie(response, token)

    return render(request, 'accounts/login.html', {
        'form': form,
        'next': safe_next_url(request) or '',
    })


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        auth_logout(request)  # audit + session record handled by signals
    messages.info(request, 'You have been signed out.')
    return redirect('accounts:login')


# --------------------------------------------------------------------------
# Profile & session management
# --------------------------------------------------------------------------
@login_required
def profile_view(request):
    user = request.user
    history = AuditLog.objects.filter(user=user, action__in=[
        Action.LOGIN, Action.FAILED_LOGIN, Action.LOGOUT, Action.SESSION_REVOKED,
        Action.PASSWORD_CHANGE, Action.PASSWORD_RESET,
    ])[:15]
    return render(request, 'accounts/profile.html', {
        'profile_user': user,
        'role_description': ROLE_DESCRIPTIONS.get(user.role, ''),
        'privilege_rows': privilege_rows(user.privileges),
        'sessions': active_sessions_for(user),
        'current_session_key': request.session.session_key,
        'devices': user.devices.all(),
        'current_device_id': devices.current_device_id(request),
        'device_limit': DevicePolicy.current().max_devices_per_user,
        'active_device_count': user.devices.filter(status=Device.Status.ACTIVE).count(),
        'history': history,
    })


@login_required
@require_POST
def logout_other_sessions_view(request):
    count = end_user_sessions(request.user, UserSession.EndReason.REVOKED,
                              exclude_key=request.session.session_key)
    if count:
        log_event(Action.SESSION_REVOKED, request=request, target='sessions:others',
                  details={'ended': count})
        messages.success(request, 'Signed out of {} other session{}.'.format(count, '' if count == 1 else 's'))
    else:
        messages.info(request, 'There are no other active sessions.')
    return redirect('accounts:profile')


@login_required
@require_POST
def revoke_session_view(request, pk):
    record = get_object_or_404(UserSession, pk=pk, user=request.user, ended_at__isnull=True)
    if record.session_key == request.session.session_key:
        messages.error(request, 'This is your current session. Use Sign out instead.')
        return redirect('accounts:profile')
    end_user_sessions(request.user, UserSession.EndReason.REVOKED, only_pks=[record.pk])
    log_event(Action.SESSION_REVOKED, request=request,
              target='session:{}'.format(record.pk), details={'device': record.device_label})
    messages.success(request, 'Session on {} ended.'.format(record.device_label))
    return redirect('accounts:profile')


class SVPasswordChangeView(auth_views.PasswordChangeView):
    form_class = SVPasswordChangeForm
    template_name = 'accounts/password_change.html'
    success_url = reverse_lazy('accounts:profile')

    def form_valid(self, form):
        old_key = self.request.session.session_key
        response = super().form_valid(form)  # keeps THIS session signed in
        new_key = self.request.session.session_key
        if old_key and new_key and old_key != new_key:
            UserSession.objects.filter(session_key=old_key).update(session_key=new_key)
        ended = end_user_sessions(self.request.user, UserSession.EndReason.PASSWORD_CHANGE,
                                  exclude_key=new_key)
        log_event(Action.PASSWORD_CHANGE, request=self.request,
                  target='user:{}'.format(self.request.user.pk),
                  details={'other_sessions_ended': ended})
        messages.success(self.request, 'Password changed. Other sessions were signed out.')
        return response


# --------------------------------------------------------------------------
# Forgot / reset password (signed, single-use, time-limited token links)
# --------------------------------------------------------------------------
class SVPasswordResetView(auth_views.PasswordResetView):
    form_class = SVPasswordResetForm
    template_name = 'accounts/password_reset_form.html'
    email_template_name = 'accounts/emails/password_reset_email.txt'
    subject_template_name = 'accounts/emails/password_reset_subject.txt'
    success_url = reverse_lazy('accounts:password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        matched = User.objects.filter(email__iexact=email, is_active=True).first()
        log_event(Action.PASSWORD_RESET_REQUEST, request=self.request, user=matched,
                  actor_label=email, result=Result.INFO,
                  details={'account_found': matched is not None})
        return super().form_valid(form)


class SVPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = 'accounts/password_reset_done.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['console_email'] = settings.EMAIL_BACKEND.endswith('console.EmailBackend')
        return context


class SVPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    form_class = SVSetPasswordForm
    template_name = 'accounts/password_reset_confirm.html'
    success_url = reverse_lazy('accounts:password_reset_complete')

    def form_valid(self, form):
        response = super().form_valid(form)
        user = form.user
        end_user_sessions(user, UserSession.EndReason.PASSWORD_RESET)
        log_event(Action.PASSWORD_RESET, request=self.request, user=user,
                  target='user:{}'.format(user.pk))
        return response


class SVPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = 'accounts/password_reset_complete.html'