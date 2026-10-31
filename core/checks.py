"""SecureVision's own deployment checks. They run together with Django's:

    python manage.py check --deploy

Errors must be fixed before real use; warnings are strong recommendations."""
from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

# Codes that appeared in examples and in conversations: never valid for real use.
PUBLISHED_EXAMPLE_CODES = {'Leader#SV-7Kq2', 'Admin#SV-9Xp4'}


@register(Tags.security, deploy=True)
def securevision_deploy_checks(app_configs=None, **kwargs):
    problems = []
    for role, code in getattr(settings, 'SV_ROLE_SIGNUP_CODES', {}).items():
        if code and (code in PUBLISHED_EXAMPLE_CODES or len(code) < 12):
            problems.append(Error(
                'The {} sign-up code is an example value or shorter than 12 characters.'.format(role),
                hint='Set a long, random SV_{}_SIGNUP_CODE in .env (or leave it empty to disable '
                     'self sign-up for that role).'.format(role), id='securevision.E001'))
    if not getattr(settings, 'SV_FILE_ENCRYPTION_KEY', ''):
        problems.append(Error(
            'SV_FILE_ENCRYPTION_KEY is not set, so protected files use the development key file.',
            hint='Generate a key, put it in SV_FILE_ENCRYPTION_KEY and keep a secure backup: '
                 'without it the stored files and evidence cannot be decrypted.', id='securevision.E002'))
    if '*' in settings.ALLOWED_HOSTS:
        problems.append(Error('ALLOWED_HOSTS contains "*".', hint='List your real host names in SV_ALLOWED_HOSTS.',
                              id='securevision.E003'))
    if not getattr(settings, 'SECURE_COOKIES', False):
        problems.append(Warning('Session and CSRF cookies are not marked Secure.',
                                hint='Serve SecureVision over HTTPS and set SV_SECURE_COOKIES=True.',
                                id='securevision.W001'))
    if settings.DATABASES['default']['ENGINE'].endswith('sqlite3'):
        problems.append(Warning('SQLite is in use.', hint='Fine for a demonstration; for several concurrent users '
                                'set SV_DB_ENGINE=postgresql.', id='securevision.W002'))
    if settings.EMAIL_BACKEND.endswith('console.EmailBackend'):
        problems.append(Warning('Password-reset emails are only printed to the console.',
                                hint='Configure SV_EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend '
                                     'and the SV_EMAIL_* settings.', id='securevision.W003'))
    if getattr(settings, 'SV_REVEAL_UNKNOWN_EMAIL', True):
        problems.append(Warning('The sign-in page says when an email address has no account.',
                                hint='Set SV_REVEAL_UNKNOWN_EMAIL=False so visitors cannot discover which '
                                     'addresses are registered.', id='securevision.W004'))
    return problems