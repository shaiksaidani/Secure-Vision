"""Phase 7 tests (Security Center, alerts, sign-in lockout): python manage.py test"""
from datetime import timedelta

from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from audit.services import log_event
from notifications.models import Notification

from .models import SecurityAlert

User = get_user_model()
STRONG = 'Secure@123'


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_LOCKOUT_ATTEMPTS=5, SV_LOCKOUT_MINUTES=15)
class SecurityTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                              full_name='Alice Rao')

    def wrong_password(self, client, times):
        for _ in range(times):
            response = client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': 'Wrong@123'})
        return response

    # ---- lockout ----------------------------------------------------------------
    def test_lockout_after_repeated_failures(self):
        client = Client()
        self.assertContains(self.wrong_password(client, 4), 'Incorrect password.')
        fifth = self.wrong_password(client, 1)
        self.assertContains(fifth, 'Too many failed sign-in attempts')
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ACCOUNT_LOCKED).exists())

        correct = client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})
        self.assertContains(correct, 'Too many failed sign-in attempts')        # even the right password
        self.assertNotIn(SESSION_KEY, client.session)

        alert = SecurityAlert.objects.get(kind=SecurityAlert.Kind.ACCOUNT_LOCKED)
        self.assertEqual(alert.user, self.alice)
        self.assertTrue(Notification.objects.filter(user=self.admin, kind=Notification.Kind.SECURITY).exists())

    def test_lock_expires(self):
        client = Client()
        self.wrong_password(client, 5)
        AuditLog.objects.filter(action=AuditLog.Action.FAILED_LOGIN).update(
            timestamp=timezone.now() - timedelta(minutes=16))
        response = client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})
        self.assertRedirects(response, reverse('core:dashboard'))

    def test_success_resets_the_count(self):
        client = Client()
        self.wrong_password(client, 4)
        client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})
        client.post(reverse('accounts:logout'))
        self.assertContains(self.wrong_password(client, 1), 'Incorrect password.')

    # ---- alerts -------------------------------------------------------------------
    def test_repeated_denials_raise_one_alert(self):
        alice = signed_in('alice@gmail.com')
        for _ in range(4):
            alice.get(reverse('accounts:user_list'))          # admin-only page -> denied each time
        alert = SecurityAlert.objects.get(kind=SecurityAlert.Kind.REPEATED_DENIALS)
        self.assertEqual(alert.user, self.alice)
        self.assertEqual(alert.severity, SecurityAlert.Severity.HIGH)
        self.assertEqual(alert.occurrences, 2)                 # 3rd denial raised it, 4th counted

    def test_integrity_failure_is_critical(self):
        log_event(AuditLog.Action.INTEGRITY_FAILURE, user=self.alice, target='file:abc',
                  result=AuditLog.Result.FAILURE)
        self.assertEqual(SecurityAlert.objects.get().severity, SecurityAlert.Severity.CRITICAL)

    # ---- Security Center ------------------------------------------------------------
    def test_center_is_admin_only_and_lists_alerts(self):
        log_event(AuditLog.Action.INTEGRITY_FAILURE, user=self.alice, target='file:abc',
                  result=AuditLog.Result.FAILURE)
        self.assertEqual(signed_in('alice@gmail.com').get(reverse('security:center')).status_code, 403)
        page = signed_in('boss@gmail.com').get(reverse('security:center'))
        self.assertContains(page, 'Protected file failed its integrity check')
        self.assertContains(page, 'Investigate')

    def test_investigate_and_resolve(self):
        log_event(AuditLog.Action.INTEGRITY_FAILURE, user=self.alice, target='file:abc',
                  result=AuditLog.Result.FAILURE)
        alert = SecurityAlert.objects.get()
        admin = signed_in('boss@gmail.com')
        page = admin.get(reverse('security:alert', args=[alert.public_id]))
        self.assertContains(page, 'Related activity')
        admin.post(reverse('security:alert_update', args=[alert.public_id]),
                   {'action': 'resolve', 'note': 'Restored from backup'})
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.RESOLVED)
        self.assertEqual(alert.handled_by, self.admin)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ALERT_UPDATED).exists())