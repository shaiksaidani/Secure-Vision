import os

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError


class SampleForm(forms.Form):
    sample = forms.FileField(
        label='Suspicious file',
        widget=forms.ClearableFileInput(attrs={'class': 'file-input'}),
        error_messages={'required': 'Choose the file you want to analyse.'})

    def clean_sample(self):
        upload = self.cleaned_data['sample']
        limit_mb = getattr(settings, 'SV_MAX_UPLOAD_MB', 25)
        if upload.size > limit_mb * 1024 * 1024:
            raise ValidationError('Files must be {} MB or smaller.'.format(limit_mb))
        if upload.size == 0:
            raise ValidationError('The file is empty.')
        self.sample_bytes = b''.join(upload.chunks())
        self.sample_name = os.path.basename(upload.name.replace('\\', '/')).strip()[:255] or 'sample'
        return upload