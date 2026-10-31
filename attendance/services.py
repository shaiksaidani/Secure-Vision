"""Attendance rules: check-in/out, late detection, day status and reports."""
import datetime as dt
from collections import defaultdict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from accounts.permissions import Privilege
from accounts.utils import describe_user_agent
from audit.models import AuditLog
from audit.services import get_client_ip, get_user_agent, log_event, session_fingerprint
from teams.models import Team

from .models import AttendanceRecord, format_duration

User = get_user_model()
Status = AttendanceRecord.Status

# Computed (not stored) day states.
NOT_CHECKED_IN = 'PENDING'
DAY_OFF = 'OFF'
JOINED = 'JOINED'


class AttendanceError(Exception):
    """A check-in/out that isn't allowed, with a message for the user."""


def today():
    return timezone.localdate()


def is_workday(day):
    return day.weekday() in settings.SV_WORK_WEEKDAYS


def late_after(day):
    """Check-ins after this moment (local time) count as Late."""
    hours, minutes = [int(part) for part in settings.SV_WORKDAY_START.split(':')]
    naive = (dt.datetime.combine(day, dt.time(hours, minutes))
             + dt.timedelta(minutes=settings.SV_LATE_GRACE_MINUTES))
    return timezone.make_aware(naive, timezone.get_current_timezone())


def _clock(moment):
    return timezone.localtime(moment).strftime('%I:%M %p')


def check_in(request):
    user, day, now = request.user, today(), timezone.now()
    with transaction.atomic():
        record = AttendanceRecord.objects.select_for_update().filter(user=user, date=day).first()
        if record and record.check_in_at:
            raise AttendanceError('You already checked in today at {}.'.format(_clock(record.check_in_at)))
        if record and record.status == Status.LEAVE:
            raise AttendanceError('Today is recorded as leave. Ask an administrator if that is wrong.')
        if record is None:
            record = AttendanceRecord(user=user, date=day)
        record.status = Status.LATE if now > late_after(day) else Status.PRESENT
        record.check_in_at = now
        record.check_in_ip = get_client_ip(request)
        record.check_in_device = describe_user_agent(get_user_agent(request))
        record.session_ref = session_fingerprint(request.session.session_key)
        record.save()
    log_event(AuditLog.Action.ATTENDANCE_CHECK_IN, request=request,
              target='attendance:{}'.format(day.isoformat()),
              details={'status': record.status, 'time': _clock(now)})
    return record


def check_out(request):
    user, day, now = request.user, today(), timezone.now()
    with transaction.atomic():
        record = AttendanceRecord.objects.select_for_update().filter(user=user, date=day).first()
        if record is None or record.check_in_at is None:
            raise AttendanceError('Check in first.')
        if record.check_out_at:
            raise AttendanceError('You already checked out today at {}.'.format(_clock(record.check_out_at)))
        record.check_out_at = now
        record.check_out_device = describe_user_agent(get_user_agent(request))
        record.save(update_fields=['check_out_at', 'check_out_device', 'updated_at'])
    log_event(AuditLog.Action.ATTENDANCE_CHECK_OUT, request=request,
              target='attendance:{}'.format(day.isoformat()),
              details={'time': _clock(now), 'worked': record.worked_label})
    return record


def first_counted_day(user):
    """An account created after that day's late cut-off isn't expected to
    attend that day, so counting starts the following day."""
    joined = timezone.localtime(user.date_joined)
    day = joined.date()
    return day if joined <= late_after(day) else day + dt.timedelta(days=1)


def day_status(record, day, today_, user=None):
    """(code, label) for one person on one day."""
    if record is not None:
        return record.status, record.get_status_display()
    if not is_workday(day):
        return DAY_OFF, 'Day off'
    if day < today_:
        if user is not None and day < first_counted_day(user):
            return JOINED, 'Joined'
        return Status.ABSENT, 'Absent'
    return NOT_CHECKED_IN, 'Not checked in'


# --------------------------------------------------------------------------
# Who a viewer may see
# --------------------------------------------------------------------------
def can_manage(viewer):
    return viewer.has_privilege(Privilege.MANAGE_ATTENDANCE)


def teams_in_scope(viewer):
    if can_manage(viewer):
        return Team.objects.order_by('name')
    if viewer.has_privilege(Privilege.VIEW_TEAM_ATTENDANCE):
        return Team.objects.filter(leader=viewer).order_by('name')
    return Team.objects.none()


def users_in_scope(viewer):
    """Admins see everyone; Team Leaders see members of the teams they lead."""
    users = User.objects.filter(is_active=True)
    if can_manage(viewer):
        return users.order_by('full_name')
    if viewer.has_privilege(Privilege.VIEW_TEAM_ATTENDANCE):
        return users.filter(team_memberships__team__leader=viewer).distinct().order_by('full_name')
    return users.none()


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
def period_bounds(period, anchor):
    if period == 'weekly':
        start = anchor - dt.timedelta(days=anchor.weekday())
        return start, start + dt.timedelta(days=6)
    if period == 'monthly':
        start = anchor.replace(day=1)
        next_month = (start + dt.timedelta(days=32)).replace(day=1)
        return start, next_month - dt.timedelta(days=1)
    return anchor, anchor


def summarize(users, start, end):
    """Per-person totals for start..end (days after today are not counted)."""
    today_ = today()
    users = list(users)
    records = defaultdict(dict)
    for record in AttendanceRecord.objects.filter(user__in=users, date__range=(start, end)):
        records[record.user_id][record.date] = record
    rows = []
    for user in users:
        joined = timezone.localtime(user.date_joined).date()
        counts = {Status.PRESENT: 0, Status.LATE: 0, Status.ABSENT: 0, Status.LEAVE: 0}
        worked = dt.timedelta()
        day = start
        while day <= min(end, today_):
            if day >= joined:
                record = records[user.pk].get(day)
                code, _label = day_status(record, day, today_, user)
                if code in counts:
                    counts[code] += 1
                if record is not None and record.worked:
                    worked += record.worked
            day += dt.timedelta(days=1)
        attended = counts[Status.PRESENT] + counts[Status.LATE]
        expected = attended + counts[Status.ABSENT]
        rows.append({
            'user': user,
            'present': counts[Status.PRESENT],
            'late': counts[Status.LATE],
            'absent': counts[Status.ABSENT],
            'leave': counts[Status.LEAVE],
            'worked': format_duration(worked),
            'rate': int(round(100.0 * attended / expected)) if expected else None,
        })
    return rows