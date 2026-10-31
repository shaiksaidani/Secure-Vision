"""Email and password rules. The server is always the authority; the
browser-side checklist in securevision.js only mirrors these rules."""
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator

EMAIL_ERROR_MESSAGE = 'Please enter a valid email address.'
PASSWORD_ERROR_MESSAGE = (
    'Password must contain at least 8 characters, including uppercase, '
    'lowercase, number and special character.'
)

# allowlist=[] means bare hosts such as "user@localhost" are rejected.
_base_email_validator = EmailValidator(message=EMAIL_ERROR_MESSAGE, allowlist=[])


def normalize_email(value):
    """Emails are stored and compared lower-case, so A@x.com == a@x.com."""
    return (value or '').strip().lower()


def validate_strict_email(value):
    """Accepts any normal address on any real domain (gmail.com, outlook.com,
    company.org, sub.example.co.in ...). Rejects user@, @gmail.com,
    user@gmail, user..name@gmail.com and similar."""
    value = (value or '').strip()
    if not value or len(value) > 254 or value.count('@') != 1:
        raise ValidationError(EMAIL_ERROR_MESSAGE, code='invalid_email')

    _base_email_validator(value)

    local, domain = value.rsplit('@', 1)
    if (not local or local.startswith('.') or local.endswith('.')
            or '..' in local or len(local) > 64):
        raise ValidationError(EMAIL_ERROR_MESSAGE, code='invalid_email')

    labels = domain.split('.')
    tld = labels[-1]
    if len(labels) < 2 or len(tld) < 2 or not tld.isalpha():
        raise ValidationError(EMAIL_ERROR_MESSAGE, code='invalid_email')


class StrongPasswordValidator:
    """8+ characters with an uppercase letter, a lowercase letter,
    a number and a special character. 'Secure@123' passes, 'secure123' fails."""

    min_length = 8

    def validate(self, password, user=None):
        password = password or ''
        checks = (
            len(password) >= self.min_length,
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any((not c.isalnum()) and (not c.isspace()) for c in password),
        )
        if not all(checks):
            raise ValidationError(PASSWORD_ERROR_MESSAGE, code='password_too_weak')

    def get_help_text(self):
        return PASSWORD_ERROR_MESSAGE