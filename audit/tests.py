"""Phase 7 tests (Activity Logs - the AUDIT TEST): python manage.py test"""
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from .models import AuditLog

User = get_user_model()
STRONG = 'Secure@123'


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


class ActivityLogTests(TestCase):
    def setUp(self):
        User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                 full_name='Boss Admin', role='ADMIN')
        User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                 full_name='Alice Rao')
        self.alice = signed_in('alice@gmail.com')
        self.alice.post(reverse('attendance:check_in'))
        self.admin = signed_in('boss@gmail.com')

    def test_admin_sees_real_events_from_everyone(self):
        page = self.admin.get(reverse('audit:activity'))
        self.assertContains(page, 'alice@gmail.com')
        self.assertContains(page, 'Checked in')
        filtered = self.admin.get(reverse('audit:activity'), {'action': 'ATTENDANCE_CHECK_IN'})
        self.assertEqual(filtered.context['page'].paginator.count, 1)

    def test_employee_sees_only_own_activity(self):
        page = self.alice.get(reverse('audit:activity'))
        self.assertContains(page, 'Checked in')
        self.assertNotContains(page, 'boss@gmail.com')
        self.assertTrue(all(e.actor_label == 'alice@gmail.com' for e in page.context['page'].object_list))

    def test_csv_export_is_admin_only_and_audited(self):
        response = self.admin.get(reverse('audit:activity'), {'export': 'csv'})
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertIn('alice@gmail.com', response.content.decode('utf-8'))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.AUDIT_EXPORTED).exists())
        not_csv = self.alice.get(reverse('audit:activity'), {'export': 'csv'})
        self.assertNotEqual(not_csv.get('Content-Type'), 'text/csv; charset=utf-8')