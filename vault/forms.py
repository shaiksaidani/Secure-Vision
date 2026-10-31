import os

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone

from teams.models import Team

from .filetypes import ACCEPT_ATTR, identify
from .models import ProtectedFile

User = get_user_model()

DATETIME_FORMAT = '%Y-%m-%dT%H:%M'


def _person_label(user):
    return '{} ({})'.format(user.full_name, user.email)



def _setup_shared_fields(form):
    """Styling and querysets shared by the upload and edit forms.

    Widgets are swapped FIRST and querysets assigned AFTER: assigning a
    queryset is what fills the widget's list of choices, so doing it the other
    way round leaves the checkbox lists empty.
    """
    for name in ('title', 'description'):
        form.fields[name].widget.attrs['class'] = 'sv-input'

    expires = form.fields['expires_at']
    expires.widget = forms.DateTimeInput(
        attrs={'type': 'datetime-local', 'class': 'sv-input'}, format=DATETIME_FORMAT)
    expires.input_formats = [DATETIME_FORMAT]
    expires.required = False
    expires.help_text = 'Leave empty for no expiry. After this time nobody can open the file.'

    teams = form.fields['allowed_teams']
    teams.widget = forms.CheckboxSelectMultiple()
    teams.queryset = Team.objects.order_by('name')
    teams.required = False
    teams.label = 'Allowed teams'

    people = form.fields['allowed_users']
    people.widget = forms.CheckboxSelectMultiple()
    people.queryset = User.objects.filter(is_active=True).order_by('full_name')
    people.label_from_instance = _person_label
    people.required = False
    people.label = 'Specific people (optional)'

    form.fields['allow_download'].label = 'Allow download (otherwise view-only in the secure viewer)'
    form.fields['visible_watermark'].label = "Show a visible watermark with the viewer's identity"
    form.fields['forensic_watermark'].label = ('Invisible forensic watermark on images '
                                               '(every person gets a uniquely marked copy)')

def _clean_future(value):
    if value and value <= timezone.now():
        raise ValidationError('The expiry date must be in the future.')
    return value


class UploadForm(forms.ModelForm):
    file = forms.FileField(
        label='File',
        widget=forms.ClearableFileInput(attrs={'accept': ACCEPT_ATTR, 'class': 'file-input'}),
        error_messages={'required': 'Choose a file to upload.'})

    class Meta:
        model = ProtectedFile
        fields = ['title', 'description', 'expires_at', 'allowed_teams', 'allowed_users',
                  'allow_download', 'visible_watermark', 'forensic_watermark']
        widgets = {'description': forms.Textarea(attrs={'rows': 2})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _setup_shared_fields(self)
        self.fields['title'].required = False
        self.fields['title'].label = 'File name'
        self.fields['title'].help_text = 'Defaults to the uploaded file name.'
        self.fields['visible_watermark'].initial = True
        self.file_bytes = None
        self.file_info = None

    def clean_file(self):
        upload = self.cleaned_data['file']
        limit_mb = getattr(settings, 'SV_MAX_UPLOAD_MB', 25)
        if upload.size > limit_mb * 1024 * 1024:
            raise ValidationError('Files must be {} MB or smaller.'.format(limit_mb))
        data = b''.join(upload.chunks())
        safe_name = os.path.basename(upload.name.replace('\\', '/')).strip()[:255]
        self.file_info = (safe_name,) + identify(safe_name, data)
        self.file_bytes = data
        return upload

    def clean_expires_at(self):
        return _clean_future(self.cleaned_data.get('expires_at'))


class FileEditForm(forms.ModelForm):
    class Meta:
        model = ProtectedFile
        fields = ['title', 'description', 'expires_at', 'allowed_teams', 'allowed_users',
                  'allow_download', 'visible_watermark', 'forensic_watermark']
        widgets = {'description': forms.Textarea(attrs={'rows': 2})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _setup_shared_fields(self)
        self.fields['title'].label = 'File name'

    def clean_title(self):
        title = ' '.join(self.cleaned_data['title'].split())
        if not title:
            raise ValidationError('Please enter a file name.')
        return title

    def clean_expires_at(self):
        value = self.cleaned_data.get('expires_at')
        # Only a NEW expiry has to be in the future, so other settings of an
        # already-expired file can still be edited.
        if 'expires_at' in self.changed_data:
            return _clean_future(value)
        return value