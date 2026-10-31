"""
SecureVision settings.

All secrets and environment-specific values come from environment variables
(optionally loaded from a local .env file). Nothing sensitive is hardcoded.
Compatible with Python 3.6 + Django 3.2 LTS.
"""
import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Minimal .env loader (avoids an extra dependency). Real environment
# variables always win over values in the file.
# --------------------------------------------------------------------------
def _load_env_file(path):
    if not path.exists():
        return
    with path.open(encoding='utf-8') as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_env_file(BASE_DIR / '.env')


def env(name, default=''):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def env_list(name, default=''):
    return [item.strip() for item in env(name, default).split(',') if item.strip()]


DEBUG = env_bool('SV_DEBUG', False)
TESTING = len(sys.argv) > 1 and sys.argv[1] == 'test'


# --------------------------------------------------------------------------
# Secret key. In development a random key is generated ONCE and persisted,
# so restarting the server does not sign everybody out.
# --------------------------------------------------------------------------
SECRET_KEY = env('SV_SECRET_KEY')
if not SECRET_KEY:
    if DEBUG or TESTING:
        key_file = BASE_DIR / '.dev_secret_key'
        if key_file.exists():
            SECRET_KEY = key_file.read_text(encoding='utf-8').strip()
        else:
            from django.core.management.utils import get_random_secret_key
            SECRET_KEY = get_random_secret_key()
            key_file.write_text(SECRET_KEY, encoding='utf-8')
    else:
        raise ImproperlyConfigured(
            'SV_SECRET_KEY must be set when SV_DEBUG is False.')

ALLOWED_HOSTS = env_list('SV_ALLOWED_HOSTS', 'localhost,127.0.0.1')


# --------------------------------------------------------------------------
# Applications
# --------------------------------------------------------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # SecureVision apps (shared by every module)
    'accounts',   # the single identity system: users, roles, sessions
    'audit',      # the single, append-only audit log
    'core',       # dashboard, navigation, shared pages
    'teams',      # teams and team membership
    'vault',      # protected files: DRM Hub, Stored Data, secure viewer
    'chat',       # confidential direct chat and team community chat
    'attendance', # check-in / check-out, team attendance and reports
    'forensics',  # invisible watermarks and the Forensic Analyzer
    'notifications',  # per-user notifications (the bell)
    'security',   # Security Center: alerts and sign-in lockout
    'incidents',  # incident management and the Evidence Vault
    'reports',    # security summary and file access reports
]


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Must come after Authentication + Messages: enforces remotely-ended sessions.
    'accounts.middleware.SessionTrackingMiddleware',
    # CSP, Permissions-Policy, no-store on signed-in pages.
    'core.middleware.SecurityHeadersMiddleware',
]

# Production without a separate web server: let WhiteNoise serve /static/
# (pip install whitenoise==5.3.0, then python manage.py collectstatic).
if env_bool('SV_SERVE_STATIC', False):
    MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

ROOT_URLCONF = 'securevision.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'core.context_processors.navigation',
            ],
        },
    },
]

WSGI_APPLICATION = 'securevision.wsgi.application'


# --------------------------------------------------------------------------
# Database: SQLite now, PostgreSQL later by changing environment variables.
# --------------------------------------------------------------------------
if env('SV_DB_ENGINE', 'sqlite').lower() == 'postgresql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': env('SV_DB_NAME'),
            'USER': env('SV_DB_USER'),
            'PASSWORD': env('SV_DB_PASSWORD'),
            'HOST': env('SV_DB_HOST', 'localhost'),
            'PORT': env('SV_DB_PORT', '5432'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': str(BASE_DIR / 'db.sqlite3'),
        }
    }

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
# The ONE user model used by every module (chat, files, attendance, audit...).
AUTH_USER_MODEL = 'accounts.User'

AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.ModelBackend']

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {'user_attributes': ('username', 'full_name', 'email')},
    },
    # 8+ chars, uppercase, lowercase, number, special character.
    {'NAME': 'accounts.validators.StrongPasswordValidator'},
]

if TESTING:
    # Fast hashing for the test suite only.
    PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'core:dashboard'
LOGOUT_REDIRECT_URL = 'accounts:login'

PASSWORD_RESET_TIMEOUT = 60 * 60  # reset links are valid for 1 hour

SV_REVEAL_UNKNOWN_EMAIL = env_bool('SV_REVEAL_UNKNOWN_EMAIL', True)

# Role authorization codes for sign-up. Choosing Team Leader or Admin in the
# sign-up dropdown requires the matching code. Empty = that role cannot be
# self-selected at sign-up (an admin must assign it in User Management).
SV_ROLE_SIGNUP_CODES = {
    'TEAM_LEADER': env('SV_TEAM_LEADER_SIGNUP_CODE'),
    'ADMIN': env('SV_ADMIN_SIGNUP_CODE'),
}
SV_TRUST_X_FORWARDED_FOR = env_bool('SV_TRUST_X_FORWARDED_FOR', False)


# --------------------------------------------------------------------------
# Sessions: server-side (database) sessions keyed to the real user ID.
# Identity always comes from request.user, never from browser state.
# --------------------------------------------------------------------------
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = int(env('SV_SESSION_AGE', str(8 * 60 * 60)))
SESSION_SAVE_EVERY_REQUEST = True          # sliding expiry while active
SESSION_EXPIRE_AT_BROWSER_CLOSE = False    # survives refresh and restarts
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_NAME = 'sv_session'

SECURE_COOKIES = env_bool('SV_SECURE_COOKIES', not DEBUG)
SESSION_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_HTTPONLY = True
CSRF_FAILURE_VIEW = 'core.views.csrf_failure'

SECURE_CONTENT_TYPE_NOSNIFF = True
# HTTPS in production (see DEPLOYMENT.md). All off by default for local development.
SECURE_SSL_REDIRECT = env_bool('SV_SSL_REDIRECT', False)
SECURE_HSTS_SECONDS = int(env('SV_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool('SV_HSTS_INCLUDE_SUBDOMAINS', False)
if env_bool('SV_BEHIND_HTTPS_PROXY', False):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_TRUSTED_ORIGINS = env_list('SV_CSRF_TRUSTED_ORIGINS', '')
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'


# --------------------------------------------------------------------------
# Email (password reset)
# --------------------------------------------------------------------------
EMAIL_BACKEND = env('SV_EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = env('SV_EMAIL_HOST')
EMAIL_PORT = int(env('SV_EMAIL_PORT', '587'))
EMAIL_HOST_USER = env('SV_EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('SV_EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = env_bool('SV_EMAIL_USE_TLS', True)
DEFAULT_FROM_EMAIL = env('SV_DEFAULT_FROM_EMAIL', 'SecureVision <no-reply@securevision.local>')


# --------------------------------------------------------------------------
# Internationalization
# --------------------------------------------------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = env('SV_TIME_ZONE', 'Asia/Kolkata')
USE_I18N = True
USE_L10N = True
USE_TZ = True


# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# --------------------------------------------------------------------------
# Protected files (DRM Hub / Stored Data)
# --------------------------------------------------------------------------
# Encrypted copies live OUTSIDE static files and are never served directly:
# every byte goes through the permission-checked vault views.
SV_PROTECTED_STORAGE = Path(env('SV_PROTECTED_STORAGE', str(BASE_DIR / 'protected_storage')))
SV_MAX_UPLOAD_MB = int(env('SV_MAX_UPLOAD_MB', '25'))
SV_EXPIRY_WARNING_DAYS = 7
# Encryption key for files at rest. Development: generated once into
# .dev_file_key. Production: set SV_FILE_ENCRYPTION_KEY (and back it up -
# without the key, stored files cannot be recovered).
SV_FILE_ENCRYPTION_KEY = env('SV_FILE_ENCRYPTION_KEY')

# --------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------
# "team": teammates can message each other, everyone can message admins and
#         admins can message anyone (default).
# "organization": any active user can message any other active user.
SV_CHAT_POLICY = env('SV_CHAT_POLICY', 'team').strip().lower()

# --------------------------------------------------------------------------
# Attendance
# --------------------------------------------------------------------------
SV_WORKDAY_START = env('SV_WORKDAY_START', '09:00')            # local time, HH:MM
SV_LATE_GRACE_MINUTES = int(env('SV_LATE_GRACE_MINUTES', '15'))  # late after start + grace
# Working days: 0 = Monday ... 6 = Sunday. Days off are never counted as Absent.
SV_WORK_WEEKDAYS = [int(d) for d in env('SV_WORK_WEEKDAYS', '0,1,2,3,4').split(',') if d.strip()]

# --------------------------------------------------------------------------
# Security Center thresholds
# --------------------------------------------------------------------------
SV_LOCKOUT_ATTEMPTS = int(env('SV_LOCKOUT_ATTEMPTS', '5'))      # failed sign-ins ...
SV_LOCKOUT_MINUTES = int(env('SV_LOCKOUT_MINUTES', '15'))       # ... within this window lock the email
SV_DENIAL_ALERT_THRESHOLD = 3       # denied accesses by one person in 10 minutes
SV_DOWNLOAD_ALERT_THRESHOLD = 10    # downloads by one person in 10 minutes
SV_SPRAY_ALERT_THRESHOLD = 10       # failed sign-ins from one IP (3+ accounts) in 15 minutes

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {'console': {'class': 'logging.StreamHandler'}},
    'loggers': {
        'securevision': {'handlers': ['console'], 'level': 'INFO'},
    },
}