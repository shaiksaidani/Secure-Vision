import os

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from accounts.forms import StyledFormMixin
from accounts.permissions import Privilege
from notifications.services import users_with_privilege
from vault.models import ProtectedFile

from .models import Incident

User = get_user_model()


def _person_label(user):
    return '{} ({})'.format(user.full_name, user.email)


class IncidentForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['title', 'summary', 'severity', 'assigned_to', 'subject_user', 'related_file']
        labels = {
            'summary': 'What happened',
            'assigned_to': 'Investigator',
            'subject_user': 'Person involved (optional)',
            'related_file': 'Protected file involved (optional)',
        }
        widgets = {'summary': forms.Textarea(attrs={'rows': 4})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_to'].queryset = users_with_privilege(Privilege.MANAGE_INCIDENTS).order_by('full_name')
        self.fields['assigned_to'].label_from_instance = _person_label
        self.fields['subject_user'].queryset = User.objects.order_by('full_name')
        self.fields['subject_user'].label_from_instance = _person_label
        self.fields['related_file'].queryset = ProtectedFile.objects.order_by('title')
        self.fields['title'].error_messages['required'] = 'Give the incident a short title.'
        self._style_fields()


class IncidentUpdateForm(StyledFormMixin, forms.Form):
    status = forms.ChoiceField(choices=Incident.Status.choices)
    severity = forms.ChoiceField(choices=Incident.Severity.choices)
    assigned_to = forms.ModelChoiceField(queryset=None, required=False, label='Investigator')
    note = forms.CharField(required=False, max_length=4000, label='Note (optional)',
                           widget=forms.Textarea(attrs={'rows': 3}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_to'].queryset = users_with_privilege(Privilege.MANAGE_INCIDENTS).order_by('full_name')
        self.fields['assigned_to'].label_from_instance = _person_label
        self._style_fields()


class EvidenceUploadForm(StyledFormMixin, forms.Form):
    file = forms.FileField(label='Evidence file', error_messages={'required': 'Choose a file.'})
    title = forms.CharField(max_length=200, required=False, label='Title (optional)')
    description = forms.CharField(max_length=2000, required=False, label='Description (optional)',
                                  widget=forms.Textarea(attrs={'rows': 2}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._style_fields()

    def clean_file(self):
        upload = self.cleaned_data['file']
        limit_mb = getattr(settings, 'SV_MAX_UPLOAD_MB', 25)
        if upload.size > limit_mb * 1024 * 1024:
            raise ValidationError('Files must be {} MB or smaller.'.format(limit_mb))
        if upload.size == 0:
            raise ValidationError('The file is empty.')
        self.file_bytes = b''.join(upload.chunks())
        self.file_name = os.path.basename(upload.name.replace('\\', '/')).strip()[:255] or 'evidence'
        self.file_mime = (getattr(upload, 'content_type', '') or 'application/octet-stream')[:100]
        return upload