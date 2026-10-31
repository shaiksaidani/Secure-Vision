from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from accounts.forms import StyledFormMixin

from .models import Team

User = get_user_model()


def _person_label(user):
    return '{} ({}) - {}'.format(user.full_name, user.email, user.get_role_display())


class TeamForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = Team
        fields = ['name', 'description', 'leader']
        labels = {'name': 'Team name', 'leader': 'Team leader'}
        widgets = {'description': forms.Textarea(attrs={'rows': 3})}
        error_messages = {'name': {'required': 'Please enter a team name.'}}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        leader = self.fields['leader']
        # Only active Team Leaders and Admins can lead a team.
        leader.queryset = User.objects.filter(
            is_active=True, role__in=[User.Role.TEAM_LEADER, User.Role.ADMIN]
        ).order_by('full_name')
        leader.required = False
        leader.empty_label = 'No leader yet'
        leader.label_from_instance = _person_label
        leader.help_text = 'Only users with the Team Leader or Admin role can be chosen.'
        leader.error_messages['invalid_choice'] = (
            'Choose an active user with the Team Leader or Admin role.')
        self.fields['description'].required = False
        self._style_fields()

    def clean_name(self):
        name = ' '.join(self.cleaned_data['name'].split())
        if len(name) < 2:
            raise ValidationError('Team name must be at least 2 characters.')
        clash = Team.objects.filter(name__iexact=name)
        if self.instance.pk:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise ValidationError('A team with this name already exists.')
        return name


class AddMembersForm(forms.Form):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        error_messages={
            'required': 'Select at least one person to add.',
            'invalid_choice': "One of the selected people can't be added "
                              '(deactivated or already a member).',
            'invalid_pk_value': 'Invalid selection.',
        })

    def __init__(self, team, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field = self.fields['users']
        # Only active users who are not already in this team.
        field.queryset = User.objects.filter(is_active=True).exclude(
            team_memberships__team=team).order_by('full_name')
        field.label_from_instance = _person_label