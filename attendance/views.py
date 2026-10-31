"""Attendance pages: my attendance, team attendance (leaders/admins) and reports."""
import csv
import datetime as dt

from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from notifications.models import Notification
from notifications.services import notify

from . import services
from .forms import MarkAttendanceForm
from .models import AttendanceRecord

Status = AttendanceRecord.Status
PERIODS = [('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')]
STATUS_FILTERS = [
    (Status.PRESENT, 'Present'), (Status.LATE, 'Late'), (Status.ABSENT, 'Absent'),
    (Status.LEAVE, 'Leave'), (services.NOT_CHECKED_IN, 'Not checked in'), (services.DAY_OFF, 'Day off'),
]


def _parse_date(value, default):
    try:
        return dt.datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return default


def _tabs(request, active):
    tabs = [{'key': 'mine', 'label': 'My attendance', 'url_name': 'attendance:mine'}]
    if request.user.has_privilege(Privilege.VIEW_TEAM_ATTENDANCE):
        tabs.append({'key': 'manage', 'label': 'Team attendance', 'url_name': 'attendance:manage'})
        tabs.append({'key': 'report', 'label': 'Reports', 'url_name': 'attendance:report'})
    for tab in tabs:
        tab['active'] = tab['key'] == active
    return tabs


# --------------------------------------------------------------------------
# My attendance
# --------------------------------------------------------------------------
@privilege_required(Privilege.CHECK_IN_OUT)
def my_attendance_view(request):
    user, today = request.user, services.today()
    record = AttendanceRecord.objects.filter(user=user, date=today).first()
    code, label = services.day_status(record, today, today, user)

    joined = timezone.localtime(user.date_joined).date()
    start = max(today - dt.timedelta(days=29), joined)
    records = {r.date: r for r in user.attendance_records.filter(date__range=(start, today))}
    history, day = [], today
    while day >= start:
        rec = records.get(day)
        day_code, day_label = services.day_status(rec, day, today, user)
        history.append({'date': day, 'record': rec, 'code': day_code, 'label': day_label})
        day -= dt.timedelta(days=1)

    month_start, month_end = services.period_bounds('monthly', today)
    return render(request, 'attendance/mine.html', {
        'tabs': _tabs(request, 'mine'),
        'today': today,
        'record': record,
        'status_code': code,
        'status_label': label,
        'can_check_in': not (record and (record.check_in_at or record.status == Status.LEAVE)),
        'can_check_out': bool(record and record.check_in_at and not record.check_out_at),
        'late_after': timezone.localtime(services.late_after(today)),
        'history': history,
        'month': services.summarize([user], month_start, month_end)[0],
    })


@privilege_required(Privilege.CHECK_IN_OUT)
@require_POST
def check_in_view(request):
    try:
        record = services.check_in(request)
    except services.AttendanceError as error:
        messages.error(request, str(error))
    else:
        late = ' You are marked Late.' if record.status == Status.LATE else ''
        clock = timezone.localtime(record.check_in_at).strftime('%I:%M %p')
        messages.success(request, 'Checked in at {}.{}'.format(clock, late))
        notify(request.user, Notification.Kind.ATTENDANCE, 'Your attendance has been recorded',
               'Checked in at {} ({}).'.format(clock, record.get_status_display()),
               url=reverse('attendance:mine'))
    return redirect('attendance:mine')


@privilege_required(Privilege.CHECK_IN_OUT)
@require_POST
def check_out_view(request):
    try:
        record = services.check_out(request)
    except services.AttendanceError as error:
        messages.error(request, str(error))
    else:
        messages.success(request, 'Checked out. You worked {} today.'.format(record.worked_label))
    return redirect('attendance:mine')


# --------------------------------------------------------------------------
# Team attendance (Team Leaders: their teams; Admins: everyone)
# --------------------------------------------------------------------------
@privilege_required(Privilege.VIEW_TEAM_ATTENDANCE)
def manage_view(request):
    today = services.today()
    day = _parse_date(request.GET.get('date'), today)
    team_id = request.GET.get('team', '')
    status_filter = request.GET.get('status', '')
    query = request.GET.get('q', '').strip()

    scope = services.users_in_scope(request.user)
    teams = services.teams_in_scope(request.user)
    users = scope.prefetch_related('team_memberships__team')
    if team_id.isdigit() and teams.filter(pk=int(team_id)).exists():
        users = users.filter(team_memberships__team_id=int(team_id)).distinct()
    if query:
        users = users.filter(Q(full_name__icontains=query) | Q(email__icontains=query))

    records = {r.user_id: r for r in AttendanceRecord.objects.filter(date=day, user__in=users)}
    rows, counts = [], {}
    for person in users:
        if timezone.localtime(person.date_joined).date() > day:
            continue
        record = records.get(person.pk)
        code, label = services.day_status(record, day, today, person)
        counts[code] = counts.get(code, 0) + 1
        if status_filter and code != status_filter:
            continue
        rows.append({'user': person, 'record': record, 'code': code, 'label': label,
                     'teams': ', '.join(m.team.name for m in person.team_memberships.all())})

    can_mark = services.can_manage(request.user)
    form = None
    if can_mark:
        form = MarkAttendanceForm(scope, initial={'date': day, 'action': 'LEAVE'})
    return render(request, 'attendance/manage.html', {
        'tabs': _tabs(request, 'manage'),
        'day': day, 'today': today, 'rows': rows,
        'summary': [(value, label, counts.get(value, 0)) for value, label in STATUS_FILTERS],
        'teams': teams, 'team_id': team_id, 'status_filter': status_filter, 'query': query,
        'status_filters': STATUS_FILTERS, 'can_mark': can_mark, 'form': form,
        'leads_no_team': not can_mark and not teams.exists(),
    })


@privilege_required(Privilege.MANAGE_ATTENDANCE)
@require_POST
def mark_view(request):
    form = MarkAttendanceForm(services.users_in_scope(request.user), request.POST)
    back = 'attendance:manage'
    if not form.is_valid():
        for errors in form.errors.values():
            for error in errors:
                messages.error(request, error)
        return redirect(back)

    person = form.cleaned_data['user']
    day = form.cleaned_data['date']
    action = form.cleaned_data['action']
    note = form.cleaned_data['note']
    record = AttendanceRecord.objects.filter(user=person, date=day).first()
    if record and record.check_in_at:
        messages.error(request, '{} checked in on {}; that record is kept as it is.'.format(
            person.full_name, day.strftime('%d %b %Y')))
        return redirect(back)

    if action == 'CLEAR':
        if record:
            record.delete()
            messages.success(request, 'Removed the mark for {} on {}.'.format(person.full_name, day.strftime('%d %b %Y')))
        else:
            messages.info(request, 'There was nothing to remove.')
    else:
        AttendanceRecord.objects.update_or_create(
            user=person, date=day,
            defaults={'status': action, 'note': note, 'marked_by': request.user})
        messages.success(request, '{} recorded as {} on {}.'.format(
            person.full_name, dict(MarkAttendanceForm.ACTIONS)[action], day.strftime('%d %b %Y')))
    notify(person, Notification.Kind.ATTENDANCE,
           'Attendance for {} updated by an administrator'.format(day.strftime('%d %b %Y')),
           'Recorded as: {}.{}'.format(dict(MarkAttendanceForm.ACTIONS)[action],
                                       ' Note: {}'.format(note) if note else ''),
           url=reverse('attendance:mine'))
    log_event(AuditLog.Action.ATTENDANCE_MARKED, request=request,
              target='attendance:{}:user:{}'.format(day.isoformat(), person.pk),
              details={'user': person.email, 'date': day.isoformat(), 'action': action, 'note': note})
    return redirect('{}?date={}'.format(reverse('attendance:manage'), day.isoformat()))


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
@privilege_required(Privilege.VIEW_TEAM_ATTENDANCE)
def report_view(request):
    today = services.today()
    period = request.GET.get('period', 'weekly')
    if period not in dict(PERIODS):
        period = 'weekly'
    anchor = _parse_date(request.GET.get('date'), today)
    team_id = request.GET.get('team', '')
    start, end = services.period_bounds(period, anchor)

    teams = services.teams_in_scope(request.user)
    users = services.users_in_scope(request.user)
    if team_id.isdigit() and teams.filter(pk=int(team_id)).exists():
        users = users.filter(team_memberships__team_id=int(team_id)).distinct()
    rows = services.summarize(users, start, end)

    if request.GET.get('export') == 'csv':
        log_event(AuditLog.Action.ATTENDANCE_EXPORTED, request=request, target='attendance:report',
                  details={'period': period, 'start': start.isoformat(), 'end': end.isoformat(),
                           'team': team_id or 'all', 'rows': len(rows)})
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="attendance_{}_{}_{}.csv"'.format(
            period, start.isoformat(), end.isoformat())
        writer = csv.writer(response)
        writer.writerow(['Employee', 'Email', 'Present', 'Late', 'Absent', 'Leave',
                         'Hours worked', 'Attendance %'])
        for row in rows:
            writer.writerow([row['user'].full_name, row['user'].email, row['present'], row['late'],
                             row['absent'], row['leave'], row['worked'],
                             '' if row['rate'] is None else row['rate']])
        return response

    return render(request, 'attendance/report.html', {
        'tabs': _tabs(request, 'report'),
        'period': period, 'periods': PERIODS, 'anchor': anchor, 'start': start, 'end': end,
        'teams': teams, 'team_id': team_id, 'rows': rows,
    })