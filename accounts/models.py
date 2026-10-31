import uuid
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.utils import timezone

from .managers import UserManager
from .permissions import privileges_for_role
from .utils import describe_user_agent
from .validators import normalize_email, validate_strict_email


class User(AbstractUser):
    """The ONE identity used by every module: chat, files, attendance, devices,
    notifications and audit all reference this table by foreign key."""

    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Admin'
        TEAM_LEADER = 'TEAM_LEADER', 'Team Leader'
        EMPLOYEE = 'EMPLOYEE', 'Employee'

    username = models.CharField(
        'username', max_length=150, unique=True,
        validators=[UnicodeUsernameValidator()],
        error_messages={'unique': 'This username is already taken.'},
    )
    email = models.EmailField(
        'email address', unique=True, validators=[validate_strict_email],
        error_messages={'unique': 'An account with this email already exists.'},
    )
    full_name = models.CharField('full name', max_length=150)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.EMPLOYEE)

    # Sign in with email.
    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name']

    objects = UserManager()

    class Meta:
        ordering = ('full_name',)

    def __str__(self):
        return '{} <{}>'.format(self.full_name or self.username, self.email)

    def save(self, *args, **kwargs):
        self.email = normalize_email(self.email)
        super().save(*args, **kwargs)

    def get_full_name(self):
        return self.full_name or self.username

    def get_short_name(self):
        return (self.full_name or self.username).split(' ')[0]

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN

    @property
    def privileges(self):
        """Privileges come from the role stored in the database, so a role
        change by an admin takes effect on the user's very next request."""
        if not self.is_active:
            return frozenset()
        return privileges_for_role(self.role)

    def has_privilege(self, code):
        return code in self.privileges

    @property
    def initials(self):
        parts = [p for p in (self.full_name or self.username).split() if p]
        letters = ''.join(p[0] for p in parts[:2])
        return (letters or '?').upper()


class UserSession(models.Model):
    """Tracks each signed-in browser session so users can see and end them.
    Device registration (Phase 5) will build on this."""

    class EndReason(models.TextChoices):
        LOGOUT = 'LOGOUT', 'Signed out'
        REVOKED = 'REVOKED', 'Ended from another session'
        PASSWORD_CHANGE = 'PASSWORD_CHANGE', 'Password changed'
        PASSWORD_RESET = 'PASSWORD_RESET', 'Password reset'
        DEACTIVATED = 'DEACTIVATED', 'Account deactivated'
        DEVICE_REVOKED = 'DEVICE_REVOKED', 'Device removed'
        EXPIRED = 'EXPIRED', 'Expired'

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tracked_sessions')
    session_key = models.CharField(max_length=40, unique=True)
    # The registered device this session was opened from (see Device below).
    device = models.ForeignKey('Device', null=True, blank=True, on_delete=models.SET_NULL,
                               related_name='sessions')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    end_reason = models.CharField(max_length=20, choices=EndReason.choices, blank=True)

    class Meta:
        ordering = ('-last_seen',)

    def __str__(self):
        return '{} ({})'.format(self.user.email, self.device_label)

    @property
    def device_label(self):
        return describe_user_agent(self.user_agent)

    @property
    def is_active(self):
        return self.ended_at is None
    

class DevicePolicy(models.Model):
    """Organization-wide device rule, edited by admins. A single row (pk=1)."""
    max_devices_per_user = models.PositiveSmallIntegerField(default=3)
    updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name='+')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'Max {} devices per account'.format(self.max_devices_per_user)

    @classmethod
    def current(cls):
        policy, _created = cls.objects.get_or_create(pk=1)
        return policy


class Device(models.Model):
    """A browser registered to an account. It is recognised by a random token
    kept in a signed, HttpOnly cookie; only a SHA-256 hash of that token is
    stored here, so the database alone cannot be used to impersonate it."""

    class Status(models.TextChoices):
        ACTIVE = 'ACTIVE', 'Active'
        REVOKED = 'REVOKED', 'Removed'

    class Kind(models.TextChoices):
        DESKTOP = 'DESKTOP', 'Desktop / laptop'
        MOBILE = 'MOBILE', 'Mobile'
        TABLET = 'TABLET', 'Tablet'

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    token_hash = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=10, choices=Kind.choices, default=Kind.DESKTOP)
    user_agent = models.CharField(max_length=300, blank=True)
    first_registered = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(default=timezone.now)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE,
                              db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name='+')

    class Meta:
        ordering = ('-last_active',)
        constraints = [
            models.UniqueConstraint(fields=['user', 'token_hash'], name='unique_device_per_user'),
        ]

    def __str__(self):
        return '{} ({})'.format(self.name, self.user.email)