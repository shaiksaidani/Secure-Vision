"""Phase 5B tests (devices): run with  python manage.py test"""
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from audit.models import AuditLog

from .devices import COOKIE_NAME
from .models import Device, DevicePolicy

User = get_user_model()
STRONG = 'Secure@123'


def make_user(email, username, full_name, role='EMPLOYEE'):
    return User.objects.create_user(email=email, username=username, password=STRONG,
                                    full_name=full_name, role=role)


def sign_in(client, email):
    return client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})


class DeviceTests(TestCase):
    def setUp(self):
        self.admin = make_user('boss@gmail.com', 'boss', 'Boss Admin', role='ADMIN')
        self.alice = make_user('alice@gmail.com', 'alice', 'Alice Rao')
        policy = DevicePolicy.current()
        policy.max_devices_per_user = 2          # the example from the requirements
        policy.save()

    # ---- registration -----------------------------------------------------------
    def test_first_sign_in_registers_device_once(self):
        laptop = Client(HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0) Chrome/120.0')
        response = sign_in(laptop, 'alice@gmail.com')
        self.assertRedirects(response, reverse('core:dashboard'))
        self.assertIn(COOKIE_NAME, response.cookies)
        self.assertTrue(response.cookies[COOKIE_NAME]['httponly'])
        device = Device.objects.get(user=self.alice)
        self.assertEqual(device.name, 'Chrome on Windows')
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.DEVICE_REGISTERED).exists())

        laptop.post(reverse('accounts:logout'))
        sign_in(laptop, 'alice@gmail.com')                 # same browser again
        self.assertEqual(Device.objects.filter(user=self.alice).count(), 1)

    # ---- the DEVICE TEST from the requirements ------------------------------------
    def test_third_device_is_blocked(self):
        sign_in(Client(), 'alice@gmail.com')                # device 1
        sign_in(Client(), 'alice@gmail.com')                # device 2
        third = Client()
        response = sign_in(third, 'alice@gmail.com')        # device 3
        self.assertContains(response, 'the maximum allowed')
        self.assertNotIn(SESSION_KEY, third.session)
        self.assertEqual(Device.objects.filter(user=self.alice).count(), 2)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.DEVICE_BLOCKED).exists())

    def test_removing_a_device_signs_it_out_and_frees_a_slot(self):
        first, second = Client(), Client()
        sign_in(first, 'alice@gmail.com')
        sign_in(second, 'alice@gmail.com')
        second_device = Device.objects.get(sessions__session_key=second.session.session_key)

        first.post(reverse('accounts:revoke_device', args=[second_device.public_id]))
        second_device.refresh_from_db()
        self.assertEqual(second_device.status, Device.Status.REVOKED)
        self.assertEqual(second.get(reverse('core:dashboard')).status_code, 302)     # signed out
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.DEVICE_REVOKED).exists())

        again = sign_in(second, 'alice@gmail.com')            # removed browser can't come back
        self.assertContains(again, 'This device was removed from your account')
        self.assertRedirects(sign_in(Client(), 'alice@gmail.com'), reverse('core:dashboard'))   # slot free

    def test_cannot_remove_current_device_or_someone_elses(self):
        mine = Client()
        sign_in(mine, 'alice@gmail.com')
        current = Device.objects.get(user=self.alice)
        mine.post(reverse('accounts:revoke_device', args=[current.public_id]))
        current.refresh_from_db()
        self.assertEqual(current.status, Device.Status.ACTIVE)

        sign_in(Client(), 'boss@gmail.com')
        admins_device = Device.objects.get(user=self.admin)
        response = mine.post(reverse('accounts:revoke_device', args=[admins_device.public_id]))
        self.assertEqual(response.status_code, 404)

    def test_profile_lists_devices(self):
        client = Client(HTTP_USER_AGENT='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari/604.1')
        sign_in(client, 'alice@gmail.com')
        page = client.get(reverse('accounts:profile'))
        self.assertContains(page, 'Registered devices')
        self.assertContains(page, 'Safari on iOS')
        self.assertContains(page, 'This device')
        self.assertContains(page, '1 of 2 allowed')

    # ---- admin --------------------------------------------------------------------
    def test_admin_sets_policy_and_removes_devices(self):
        employee = Client()
        sign_in(employee, 'alice@gmail.com')
        self.assertEqual(employee.get(reverse('accounts:devices')).status_code, 403)

        admin = Client()
        sign_in(admin, 'boss@gmail.com')
        page = admin.get(reverse('accounts:devices'))
        self.assertContains(page, 'alice@gmail.com')

        admin.post(reverse('accounts:devices'), {'max_devices_per_user': 1})
        self.assertEqual(DevicePolicy.current().max_devices_per_user, 1)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.DEVICE_POLICY_CHANGED).exists())
        self.assertContains(sign_in(Client(), 'alice@gmail.com'), 'the maximum allowed')

        device = Device.objects.get(user=self.alice)
        admin.post(reverse('accounts:admin_revoke_device', args=[device.public_id]))
        self.assertEqual(employee.get(reverse('core:dashboard')).status_code, 302)

    def test_policy_must_be_between_1_and_10(self):
        admin = Client()
        sign_in(admin, 'boss@gmail.com')
        response = admin.post(reverse('accounts:devices'), {'max_devices_per_user': 0})
        self.assertContains(response, 'Choose a number between 1 and 10.')
        self.assertEqual(DevicePolicy.current().max_devices_per_user, 2)