import hmac

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError

from .permissions import ROLE_DESCRIPTIONS
from .validators import normalize_email, validate_strict_email

User = get_user_model()

UNKNOWN_EMAIL_MESSAGE = 'No account found with this email.'

# Order shown in the sign-up dropdown (Employee first, the safe default).
SIGNUP_ROLE_CHOICES = [
    (User.Role.EMPLOYEE.value, User.Role.EMPLOYEE.label),
    (User.Role.TEAM_LEADER.value, User.Role.TEAM_LEADER.label),
    (User.Role.ADMIN.value, User.Role.ADMIN.label),
]


class StyledFormMixin:
    """Adds the shared input class to every widget."""

    def _style_fields(self):
        for field in self.fields.values():
            existing = field.widget.attrs.get('class', '')
            field.widget.attrs['class'] = (existing + ' sv-input').strip()


def _email_field(autofocus=False):
    attrs = {'autocomplete': 'email', 'inputmode': 'email', 'spellcheck': 'false'}
    if autofocus:
        attrs['autofocus'] = True
    # CharField (not EmailField) so users see exactly one consistent message.
    return forms.CharField(
        label='Email', max_length=254,
        widget=forms.EmailInput(attrs=attrs),
        error_messages={'required': 'Please enter your email address.'})


def _clean_email_value(value):
    value = normalize_email(value)
    validate_strict_email(value)
    return value


class SignupForm(StyledFormMixin, forms.Form):
    full_name = forms.CharField(
        label='Full name', max_length=150,
        widget=forms.TextInput(attrs={'autocomplete': 'name', 'autofocus': True}),
        error_messages={'required': 'Please enter your full name.'})
    username = forms.CharField(
        label='Username', max_length=150,
        validators=[UnicodeUsernameValidator()],
        help_text='Letters, numbers and @ . + - _ only.',
        widget=forms.TextInput(attrs={'autocomplete': 'username', 'spellcheck': 'false'}),
        error_messages={'required': 'Please choose a username.'})
    email = _email_field()
    role = forms.ChoiceField(
        label='Role', choices=SIGNUP_ROLE_CHOICES, initial=User.Role.EMPLOYEE.value,
        widget=forms.Select(attrs={'data-role-select': ''}),
        error_messages={'required': 'Please choose a role.',
                        'invalid_choice': 'Please choose a valid role.'})
    role_code = forms.CharField(
        label='Role authorization code', required=False, strip=True,
        help_text='Required for Team Leader and Admin. Your organization gives you this code.',
        widget=forms.PasswordInput(attrs={'autocomplete': 'off'}))
    password1 = forms.CharField(
        label='Password', strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        error_messages={'required': 'Please choose a password.'})
    password2 = forms.CharField(
        label='Confirm password', strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        error_messages={'required': 'Please confirm your password.'})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.role_code_rejected = None  # set when a privileged-role code fails
        self._style_fields()

    @property
    def role_descriptions(self):
        return [(value, label, ROLE_DESCRIPTIONS.get(value, ''))
                for value, label in SIGNUP_ROLE_CHOICES]

    def clean_full_name(self):
        value = ' '.join(self.cleaned_data['full_name'].split())
        if len(value) < 2:
            raise ValidationError('Please enter your full name.')
        return value

    def clean_username(self):
        value = self.cleaned_data['username'].strip()
        if User.objects.filter(username__iexact=value).exists():
            raise ValidationError('This username is already taken.')
        return value

    def clean_email(self):
        value = _clean_email_value(self.cleaned_data['email'])
        if User.objects.filter(email__iexact=value).exists():
            raise ValidationError('An account with this email already exists.')
        return value

    def _clean_role(self, cleaned):
        """Employee needs nothing extra. Team Leader / Admin need the matching
        authorization code from settings (compared in constant time)."""
        role = cleaned.get('role')
        if not role or role == User.Role.EMPLOYEE:
            return
        label = dict(SIGNUP_ROLE_CHOICES)[role]
        expected = (getattr(settings, 'SV_ROLE_SIGNUP_CODES', {}) or {}).get(role, '')
        supplied = cleaned.get('role_code', '')
        if not expected:
            self.add_error('role', '{} accounts cannot be created by sign-up. '
                                   'Sign up as Employee and ask an administrator '
                                   'to assign this role.'.format(label))
        elif not supplied:
            self.add_error('role_code', 'Enter the authorization code for the {} role.'.format(label))
        elif not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
            self.role_code_rejected = role
            self.add_error('role_code', 'Incorrect authorization code for the {} role.'.format(label))

    def clean(self):
        cleaned = super().clean()
        self._clean_role(cleaned)
        password1 = cleaned.get('password1')
        password2 = cleaned.get('password2')
        if password1 and password2 and password1 != password2:
            self.add_error('password2', 'Passwords do not match.')
        if password1:
            candidate = User(
                username=cleaned.get('username', ''),
                email=cleaned.get('email', ''),
                full_name=cleaned.get('full_name', ''))
            try:
                password_validation.validate_password(password1, candidate)
            except ValidationError as error:
                self.add_error('password1', error)
        return cleaned

    def save(self):
        return User.objects.create_user(
            email=self.cleaned_data['email'],
            username=self.cleaned_data['username'],
            password=self.cleaned_data['password1'],
            full_name=self.cleaned_data['full_name'],
            role=self.cleaned_data['role'],  # validated in _clean_role()
        )


class LoginForm(StyledFormMixin, forms.Form):
    email = _email_field(autofocus=True)
    password = forms.CharField(
        label='Password', strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
        error_messages={'required': 'Please enter your password.'})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._style_fields()

    def clean_email(self):
        return _clean_email_value(self.cleaned_data['email'])


class SVPasswordResetForm(StyledFormMixin, PasswordResetForm):
    email = _email_field(autofocus=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._style_fields()

    def clean_email(self):
        value = _clean_email_value(self.cleaned_data['email'])
        if getattr(settings, 'SV_REVEAL_UNKNOWN_EMAIL', True):
            if not User.objects.filter(email__iexact=value, is_active=True).exists():
                raise ValidationError(UNKNOWN_EMAIL_MESSAGE)
        return value


class SVSetPasswordForm(StyledFormMixin, SetPasswordForm):
    error_messages = dict(SetPasswordForm.error_messages,
                          password_mismatch='Passwords do not match.')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].help_text = ''
        self._style_fields()


class SVPasswordChangeForm(StyledFormMixin, PasswordChangeForm):
    error_messages = dict(PasswordChangeForm.error_messages,
                          password_mismatch='Passwords do not match.',
                          password_incorrect='Your current password is incorrect.')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].help_text = ''
        self._style_fields()