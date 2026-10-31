"""Phase 5A tests (attendance): run with  python manage.py test"""
import datetime as dt

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from teams.models import Team, TeamMembership

from .models import AttendanceRecord

User = get_user_model()
STRONG = 'Secure@123'
EVERY_DAY = [0, 1, 2, 3, 4, 5, 6]


def make_user(email, username, full_name, role='EMPLOYEE'):
    return User.objects.create_user(email=email, username=username, password=STRONG,
                                    full_name=full_name, role=role)


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


# Workday starts at midnight with a full day of grace: nobody is late unless a test says so.
@override_settings(SV_WORK_WEEKDAYS=EVERY_DAY, SV_WORKDAY_START='00:00', SV_LATE_GRACE_MINUTES=1440)
class AttendanceTests(TestCase):
    def setUp(self):
        self.admin = make_user('boss@gmail.com', 'boss', 'Boss Admin', role='ADMIN')
        self.leader = make_user('lead@gmail.com', 'lead', 'Lena Lead', role='TEAM_LEADER')
        self.alice = make_user('alice@gmail.com', 'alice', 'Alice Rao')
        self.carol = make_user('carol@gmail.com', 'carol', 'Carol Das')
        alpha = Team.objects.create(name='Team Alpha', leader=self.leader)
        beta = Team.objects.create(name='Team Beta')
        TeamMembership.objects.create(team=alpha, user=self.leader)
        TeamMembership.objects.create(team=alpha, user=self.alice)
        TeamMembership.objects.create(team=beta, user=self.carol)
        self.admin_client = signed_in('boss@gmail.com')
        self.alice_client = signed_in('alice@gmail.com')

    def today(self):
        return timezone.localdate()

    # ---- the ATTENDANCE TEST from the requirements --------------------------
    def test_check_in_survives_refresh_and_check_out_records_duration(self):
        response = self.alice_client.post(reverse('attendance:check_in'))
        self.assertRedirects(response, reverse('attendance:mine'))
        for _ in range(2):   # refresh
            page = self.alice_client.get(reverse('attendance:mine'))
            self.assertContains(page, 'Present')
        record = AttendanceRecord.objects.get(user=self.alice, date=self.today())
        self.assertEqual(record.status, AttendanceRecord.Status.PRESENT)
        self.assertIsNotNone(record.check_in_at)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.ATTENDANCE_CHECK_IN).exists())

        again = self.alice_client.post(reverse('attendance:check_in'), follow=True)
        self.assertContains(again, 'You already checked in today')
        self.assertEqual(AttendanceRecord.objects.filter(user=self.alice).count(), 1)

        done = self.alice_client.post(reverse('attendance:check_out'), follow=True)
        self.assertContains(done, 'You worked')
        record.refresh_from_db()
        self.assertIsNotNone(record.check_out_at)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.ATTENDANCE_CHECK_OUT).exists())

        admin_page = self.admin_client.get(reverse('attendance:manage'))
        self.assertContains(admin_page, 'Alice Rao')
        alice_row = [row for row in admin_page.context['rows'] if row['user'] == self.alice][0]
        self.assertEqual(alice_row['code'], AttendanceRecord.Status.PRESENT)

    def test_check_out_needs_check_in(self):
        response = self.alice_client.post(reverse('attendance:check_out'), follow=True)
        self.assertContains(response, 'Check in first.')
        self.assertFalse(AttendanceRecord.objects.exists())

    @override_settings(SV_WORKDAY_START='00:00', SV_LATE_GRACE_MINUTES=0)
    def test_late_check_in(self):
        self.alice_client.post(reverse('attendance:check_in'))
        self.assertEqual(AttendanceRecord.objects.get(user=self.alice).status, AttendanceRecord.Status.LATE)

    # ---- who can see what ----------------------------------------------------
    def test_employee_cannot_open_team_attendance(self):
        self.assertEqual(self.alice_client.get(reverse('attendance:manage')).status_code, 403)
        self.assertEqual(self.alice_client.get(reverse('attendance:report')).status_code, 403)

    def test_team_leader_sees_only_own_team(self):
        page = signed_in('lead@gmail.com').get(reverse('attendance:manage'))
        self.assertContains(page, 'Alice Rao')
        self.assertNotContains(page, 'Carol Das')
        self.assertNotContains(page, 'Record leave or absence')   # leaders can't mark

    # ---- leave / absence -------------------------------------------------------
    def test_admin_marks_leave_and_check_in_is_refused(self):
        self.admin_client.post(reverse('attendance:mark'), {
            'user': self.alice.pk, 'date': self.today().isoformat(), 'action': 'LEAVE', 'note': 'Medical'})
        record = AttendanceRecord.objects.get(user=self.alice, date=self.today())
        self.assertEqual(record.status, AttendanceRecord.Status.LEAVE)
        self.assertEqual(record.marked_by, self.admin)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ATTENDANCE_MARKED).exists())

        response = self.alice_client.post(reverse('attendance:check_in'), follow=True)
        self.assertContains(response, 'Today is recorded as leave.')
        record.refresh_from_db()
        self.assertIsNone(record.check_in_at)

    def test_mark_never_overwrites_a_real_check_in(self):
        self.alice_client.post(reverse('attendance:check_in'))
        self.admin_client.post(reverse('attendance:mark'), {
            'user': self.alice.pk, 'date': self.today().isoformat(), 'action': 'ABSENT'})
        self.assertEqual(AttendanceRecord.objects.get(user=self.alice).status, AttendanceRecord.Status.PRESENT)

    def test_employee_cannot_mark(self):
        response = self.alice_client.post(reverse('attendance:mark'), {
            'user': self.carol.pk, 'date': self.today().isoformat(), 'action': 'ABSENT'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AttendanceRecord.objects.exists())

    # ---- reports ---------------------------------------------------------------
    def test_missed_workday_counts_as_absent(self):
        User.objects.filter(pk=self.alice.pk).update(date_joined=timezone.now() - dt.timedelta(days=3))
        yesterday = self.today() - dt.timedelta(days=1)
        page = self.admin_client.get(reverse('attendance:report'),
                                     {'period': 'daily', 'date': yesterday.isoformat()})
        alice_row = [row for row in page.context['rows'] if row['user'] == self.alice][0]
        self.assertEqual(alice_row['absent'], 1)
        self.assertEqual(alice_row['rate'], 0)

    @override_settings(SV_WORKDAY_START='00:00', SV_LATE_GRACE_MINUTES=0)
    def test_joining_day_after_cut_off_is_not_absent(self):
        User.objects.filter(pk=self.alice.pk).update(date_joined=timezone.now() - dt.timedelta(days=1))
        yesterday = self.today() - dt.timedelta(days=1)
        page = self.admin_client.get(reverse('attendance:report'),
                                     {'period': 'daily', 'date': yesterday.isoformat()})
        alice_row = [row for row in page.context['rows'] if row['user'] == self.alice][0]
        self.assertEqual(alice_row['absent'], 0)
        self.assertContains(self.alice_client.get(reverse('attendance:mine')), 'Joined')

    def test_csv_export_is_audited(self):
        self.alice_client.post(reverse('attendance:check_in'))
        response = self.admin_client.get(reverse('attendance:report'), {'period': 'monthly', 'export': 'csv'})
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertIn('Alice Rao', response.content.decode('utf-8'))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ATTENDANCE_EXPORTED).exists())

    # ---- dashboard -------------------------------------------------------------
    def test_dashboard_shows_todays_attendance(self):
        page = self.alice_client.get(reverse('core:dashboard'))
        self.assertContains(page, "Today's attendance")
        self.assertContains(page, 'Not checked in')
        self.alice_client.post(reverse('attendance:check_in'))
        self.assertContains(self.alice_client.get(reverse('core:dashboard')), 'In at')