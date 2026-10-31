from django import forms

from accounts.forms import StyledFormMixin


class MarkAttendanceForm(StyledFormMixin, forms.Form):
    """Admins record leave or absence for a day the person did not check in."""
    ACTIONS = [
        ('LEAVE', 'Leave'),
        ('ABSENT', 'Absent'),
        ('CLEAR', 'Remove a leave/absence mark'),
    ]

    user = forms.ModelChoiceField(queryset=None, label='Employee',
                                  error_messages={'required': 'Choose an employee.',
                                                  'invalid_choice': 'Choose an employee from the list.'})
    date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
                           input_formats=['%Y-%m-%d'],
                           error_messages={'required': 'Choose a date.'})
    action = forms.ChoiceField(choices=ACTIONS, label='Record as')
    note = forms.CharField(max_length=255, required=False, label='Note (optional)')

    def __init__(self, users, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = users
        self.fields['user'].label_from_instance = lambda u: '{} ({})'.format(u.full_name, u.email)
        self._style_fields()