"""Device pages: users remove their own devices (Profile); admins set the
device policy and can remove any device (Devices page)."""
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from audit.models import AuditLog
from audit.services import log_event

from . import devices
from .decorators import privilege_required
from .forms import StyledFormMixin
from .models import Device, DevicePolicy
from .permissions import Privilege


class DevicePolicyForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = DevicePolicy
        fields = ['max_devices_per_user']
        labels = {'max_devices_per_user': 'Maximum devices per account'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field = self.fields['max_devices_per_user']
        field.min_value = 1
        field.max_value = 10
        field.widget.attrs.update({'min': 1, 'max': 10})
        field.help_text = 'Between 1 and 10. Existing devices are kept; new ones are refused once the limit is reached.'
        self._style_fields()

    def clean_max_devices_per_user(self):
        value = self.cleaned_data['max_devices_per_user']
        if not 1 <= value <= 10:
            raise forms.ValidationError('Choose a number between 1 and 10.')
        return value


@login_required
@require_POST
def revoke_own_device_view(request, public_id):
    device = get_object_or_404(Device, public_id=public_id, user=request.user)
    if device.pk == devices.current_device_id(request):
        messages.error(request, "This is the device you're using now. Sign out instead.")
    elif device.status == Device.Status.REVOKED:
        messages.info(request, 'That device was already removed.')
    else:
        devices.revoke(device, request)
        messages.success(request, '{} removed. It has been signed out and can no longer sign in.'.format(device.name))
    return redirect('accounts:profile')


@privilege_required(Privilege.MANAGE_DEVICE_POLICY)
def device_admin_view(request):
    policy = DevicePolicy.current()
    before = policy.max_devices_per_user
    form = DevicePolicyForm(request.POST or None, instance=policy)
    if request.method == 'POST' and form.is_valid():
        policy = form.save(commit=False)
        policy.updated_by = request.user
        policy.save()
        if policy.max_devices_per_user != before:
            log_event(AuditLog.Action.DEVICE_POLICY_CHANGED, request=request, target='device-policy',
                      details={'old_max': before, 'new_max': policy.max_devices_per_user})
            messages.success(request, 'Device limit set to {} per account.'.format(policy.max_devices_per_user))
        else:
            messages.info(request, 'No changes to save.')
        return redirect('accounts:devices')

    query = request.GET.get('q', '').strip()
    status = request.GET.get('status', '')
    device_list = Device.objects.select_related('user', 'revoked_by').order_by('user__full_name', '-last_active')
    if query:
        device_list = device_list.filter(Q(user__full_name__icontains=query) | Q(user__email__icontains=query)
                                         | Q(name__icontains=query))
    if status in Device.Status.values:
        device_list = device_list.filter(status=status)
    return render(request, 'accounts/devices_admin.html', {
        'form': form, 'policy': policy, 'devices': device_list[:300], 'query': query, 'status': status,
        'status_choices': Device.Status.choices, 'current_device_id': devices.current_device_id(request),
        'active_count': Device.objects.filter(status=Device.Status.ACTIVE).count(),
    })


@privilege_required(Privilege.MANAGE_DEVICE_POLICY)
@require_POST
def admin_revoke_device_view(request, public_id):
    device = get_object_or_404(Device.objects.select_related('user'), public_id=public_id)
    if device.pk == devices.current_device_id(request):
        messages.error(request, "That's the device you're using now. Sign out instead.")
    elif device.status == Device.Status.REVOKED:
        messages.info(request, 'That device was already removed.')
    else:
        ended = devices.revoke(device, request)
        messages.success(request, "{}'s {} removed ({} session{} ended).".format(
            device.user.full_name, device.name, ended, '' if ended == 1 else 's'))
    return redirect('accounts:devices')