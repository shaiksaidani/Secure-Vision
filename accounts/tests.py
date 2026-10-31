"""Phase 1 tests: run with  python manage.py test"""
import re

from django.contrib.auth import SESSION_KEY, get_user_model, password_validation
from django.core import mail
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog

from .models import UserSession
from .permissions import Privilege
from .validators import StrongPasswordValidator, validate_strict_email

User = get_user_model()
STRONG = 'Secure@123'


def make_user(email='alice@gmail.com', username='alice', full_name='Alice Rao',
              password=STRONG, **extra):
    return User.objects.create_user(email=email, username=username, password=password,
                                    full_name=full_name, **extra)


class EmailValidationTests(TestCase):
    def test_accepts_normal_addresses(self):
        for email in ['user@gmail.com', 'name123@gmail.com', 'student@outlook.com',
                      'employee@company.org', 'first.last@mail.example.co.in',
                      'x+tag@proton.me']:
            with self.subTest(email=email):
                validate_strict_email(email)

    def test_rejects_invalid_addresses(self):
        for email in ['user@', '@gmail.com', 'user@gmail', 'user..name@gmail.com',
                      '.user@gmail.com', 'user.@gmail.com', 'user@gmail.c',
                      'plainaddress', 'user@@gmail.com', 'user@localhost', '']:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    validate_strict_email(email)


class PasswordRuleTests(TestCase):
    def test_strong_password_accepted(self):
        StrongPasswordValidator().validate(STRONG)
        password_validation.validate_password(STRONG, User(username='bob', email='bob@gmail.com', full_name='Bob'))

    def test_weak_passwords_rejected(self):
        for pw in ['secure123', 'Secure123', 'SECURE@123', 'Secure@abc', 'Se@1', 'secure@123']:
            with self.subTest(pw=pw):
                with self.assertRaises(ValidationError):
                    StrongPasswordValidator().validate(pw)


class SignupTests(TestCase):
    def post_signup(self, **overrides):
        data = {'full_name': 'Alice Rao', 'username': 'alice', 'email': 'alice@gmail.com',
                'role': 'EMPLOYEE', 'password1': STRONG, 'password2': STRONG}
        data.update(overrides)
        return self.client.post(reverse('accounts:signup'), data)

    def test_signup_creates_real_employee_and_redirects_to_login(self):
        response = self.post_signup()
        self.assertRedirects(response, reverse('accounts:login'))
        user = User.objects.get(email='alice@gmail.com')
        self.assertEqual(user.role, User.Role.EMPLOYEE)
        self.assertNotEqual(user.password, STRONG)          # hashed, not plain text
        self.assertTrue(user.check_password(STRONG))
        self.assertTrue(AuditLog.objects.filter(user=user, action=AuditLog.Action.SIGNUP).exists())

    def test_duplicate_email_is_case_insensitive(self):
        make_user()
        response = self.post_signup(email='ALICE@Gmail.com', username='alice2')
        self.assertContains(response, 'An account with this email already exists.')
        self.assertEqual(User.objects.count(), 1)

    def test_duplicate_username(self):
        make_user()
        response = self.post_signup(email='other@gmail.com', username='ALICE')
        self.assertContains(response, 'This username is already taken.')

    def test_weak_password_shows_rule_message(self):
        response = self.post_signup(password1='secure123', password2='secure123')
        self.assertContains(response, 'Password must contain at least 8 characters')
        self.assertFalse(User.objects.exists())

    def test_password_mismatch(self):
        response = self.post_signup(password2='Secure@124')
        self.assertContains(response, 'Passwords do not match.')

    def test_invalid_email_message(self):
        response = self.post_signup(email='user@gmail')
        self.assertContains(response, 'Please enter a valid email address.')


class LoginTests(TestCase):
    def setUp(self):
        self.alice = make_user()
        self.bob = make_user(email='bob@outlook.com', username='bob', full_name='Bob Khan')

    def login(self, email, password=STRONG, client=None, **extra):
        client = client or self.client
        data = {'email': email, 'password': password}
        data.update(extra)
        return client.post(reverse('accounts:login'), data)

    def test_identity_survives_refresh(self):
        response = self.login('alice@gmail.com')
        self.assertRedirects(response, reverse('core:dashboard'))
        for _ in range(3):  # three "refreshes"
            page = self.client.get(reverse('core:dashboard'))
            self.assertEqual(page.status_code, 200)
            self.assertContains(page, 'alice@gmail.com')
            self.assertNotContains(page, 'unknown@gmail.com')
            self.assertEqual(int(self.client.session[SESSION_KEY]), self.alice.pk)

    def test_login_is_case_insensitive_on_email(self):
        response = self.login('  Alice@GMAIL.com ')
        self.assertRedirects(response, reverse('core:dashboard'))

    def test_switching_users_shows_each_own_profile(self):
        self.login('alice@gmail.com')
        self.assertContains(self.client.get(reverse('accounts:profile')), 'Alice Rao')
        self.client.post(reverse('accounts:logout'))
        self.login('bob@outlook.com')
        profile = self.client.get(reverse('accounts:profile'))
        self.assertContains(profile, 'bob@outlook.com')
        self.assertContains(profile, 'Bob Khan')
        self.assertNotContains(profile, 'alice@gmail.com')

    def test_unknown_email(self):
        response = self.login('nobody@gmail.com')
        self.assertContains(response, 'No account found with this email.')
        self.assertTrue(AuditLog.objects.filter(
            action=AuditLog.Action.FAILED_LOGIN, actor_label='nobody@gmail.com').exists())

    @override_settings(SV_REVEAL_UNKNOWN_EMAIL=False)
    def test_unknown_email_generic_when_configured(self):
        response = self.login('nobody@gmail.com')
        self.assertContains(response, 'Incorrect email or password.')

    def test_wrong_password(self):
        response = self.login('alice@gmail.com', password='Wrong@1234')
        self.assertContains(response, 'Incorrect password.')
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertTrue(AuditLog.objects.filter(
            user=self.alice, action=AuditLog.Action.FAILED_LOGIN).exists())

    def test_invalid_email_format(self):
        response = self.login('user@')
        self.assertContains(response, 'Please enter a valid email address.')

    def test_inactive_account_cannot_sign_in(self):
        self.alice.is_active = False
        self.alice.save()
        response = self.login('alice@gmail.com')
        self.assertContains(response, 'This account has been deactivated.')

    def test_login_records_session_and_audit(self):
        self.login('alice@gmail.com')
        self.assertTrue(UserSession.objects.filter(user=self.alice, ended_at__isnull=True).exists())
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.LOGIN).exists())

    def test_logout_requires_post_and_is_audited(self):
        self.login('alice@gmail.com')
        self.assertEqual(self.client.get(reverse('accounts:logout')).status_code, 405)
        self.client.post(reverse('accounts:logout'))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.LOGOUT).exists())
        self.assertRedirects(self.client.get(reverse('core:dashboard')),
                             reverse('accounts:login') + '?next=' + reverse('core:dashboard'))

    def test_next_parameter_cannot_redirect_off_site(self):
        response = self.login('alice@gmail.com', next='https://evil.example.com/')
        self.assertRedirects(response, reverse('core:dashboard'))

    def test_pages_require_login(self):
        for name in ['core:dashboard', 'accounts:profile', 'accounts:password_change']:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('accounts:login'), response['Location'])


class SessionManagementTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.laptop = Client(HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0) Chrome/120.0')
        self.phone = Client(HTTP_USER_AGENT='Mozilla/5.0 (Linux; Android 13; Mobile) Chrome/120.0')
        for c in (self.laptop, self.phone):
            c.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})

    def test_sign_out_other_sessions(self):
        self.laptop.post(reverse('accounts:logout_other_sessions'))
        self.assertEqual(self.laptop.get(reverse('core:dashboard')).status_code, 200)
        self.assertEqual(self.phone.get(reverse('core:dashboard')).status_code, 302)

    def test_end_single_session(self):
        phone_key = self.phone.session.session_key
        record = UserSession.objects.get(session_key=phone_key)
        self.laptop.post(reverse('accounts:revoke_session', args=[record.pk]))
        self.assertEqual(self.phone.get(reverse('core:dashboard')).status_code, 302)

    def test_cannot_end_another_users_session(self):
        other = make_user(email='eve@gmail.com', username='eve', full_name='Eve')
        eve = Client()
        eve.post(reverse('accounts:login'), {'email': 'eve@gmail.com', 'password': STRONG})
        record = UserSession.objects.filter(user=self.user).first()
        response = eve.post(reverse('accounts:revoke_session', args=[record.pk]))
        self.assertEqual(response.status_code, 404)
        self.assertIsNotNone(other.pk)

    def test_password_change_keeps_current_and_ends_others(self):
        response = self.laptop.post(reverse('accounts:password_change'), {
            'old_password': STRONG, 'new_password1': 'Better#456', 'new_password2': 'Better#456'})
        self.assertRedirects(response, reverse('accounts:profile'))
        self.assertEqual(self.laptop.get(reverse('core:dashboard')).status_code, 200)
        self.assertEqual(self.phone.get(reverse('core:dashboard')).status_code, 302)
        self.assertTrue(AuditLog.objects.filter(user=self.user, action=AuditLog.Action.PASSWORD_CHANGE).exists())

    def test_profile_lists_sessions(self):
        page = self.laptop.get(reverse('accounts:profile'))
        self.assertContains(page, 'Chrome on Windows')
        self.assertContains(page, 'Chrome on Android')
        self.assertContains(page, 'This session')


class PasswordResetTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def test_full_reset_flow(self):
        response = self.client.post(reverse('accounts:password_reset'), {'email': 'alice@gmail.com'})
        self.assertRedirects(response, reverse('accounts:password_reset_done'))
        self.assertEqual(len(mail.outbox), 1)
        link = re.search(r'http://testserver(/accounts/reset/\S+/)', mail.outbox[0].body).group(1)

        page = self.client.get(link, follow=True)
        set_password_url = page.redirect_chain[-1][0]
        self.assertContains(page, 'Set a new password')

        done = self.client.post(set_password_url, {'new_password1': 'Fresh!789', 'new_password2': 'Fresh!789'})
        self.assertRedirects(done, reverse('accounts:password_reset_complete'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Fresh!789'))
        self.assertTrue(AuditLog.objects.filter(user=self.user, action=AuditLog.Action.PASSWORD_RESET).exists())

    def test_reset_rejects_weak_password(self):
        self.client.post(reverse('accounts:password_reset'), {'email': 'alice@gmail.com'})
        link = re.search(r'http://testserver(/accounts/reset/\S+/)', mail.outbox[0].body).group(1)
        page = self.client.get(link, follow=True)
        response = self.client.post(page.redirect_chain[-1][0],
                                    {'new_password1': 'weakpass', 'new_password2': 'weakpass'})
        self.assertContains(response, 'Password must contain at least 8 characters')

    def test_unknown_email(self):
        response = self.client.post(reverse('accounts:password_reset'), {'email': 'ghost@gmail.com'})
        self.assertContains(response, 'No account found with this email.')
        self.assertEqual(len(mail.outbox), 0)


class AuditIntegrityTests(TestCase):
    def test_entries_are_append_only(self):
        entry = AuditLog.objects.create(action=AuditLog.Action.LOGIN, actor_label='x@gmail.com')
        with self.assertRaises(ValueError):
            entry.save()
        with self.assertRaises(ValueError):
            entry.delete()

    def test_raw_session_key_is_never_stored(self):
        make_user()
        self.client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})
        key = self.client.session.session_key
        entry = AuditLog.objects.filter(action=AuditLog.Action.LOGIN).first()
        self.assertTrue(entry.session_ref)
        self.assertNotIn(entry.session_ref, key)


ROLE_CODES = {'TEAM_LEADER': 'Leader-Code-2026', 'ADMIN': 'Admin-Code-2026'}


@override_settings(SV_ROLE_SIGNUP_CODES=ROLE_CODES)
class RoleSignupTests(TestCase):
    def post_signup(self, role, code=''):
        return self.client.post(reverse('accounts:signup'), {
            'full_name': 'Ravi Kumar', 'username': 'ravi', 'email': 'ravi@gmail.com',
            'role': role, 'role_code': code, 'password1': STRONG, 'password2': STRONG})

    def test_signup_page_shows_role_dropdown(self):
        page = self.client.get(reverse('accounts:signup'))
        for label in ['Employee', 'Team Leader', 'Admin']:
            self.assertContains(page, label)

    def test_employee_needs_no_code(self):
        self.assertRedirects(self.post_signup('EMPLOYEE'), reverse('accounts:login'))
        self.assertEqual(User.objects.get(email='ravi@gmail.com').role, 'EMPLOYEE')

    def test_admin_with_correct_code(self):
        self.assertRedirects(self.post_signup('ADMIN', 'Admin-Code-2026'), reverse('accounts:login'))
        self.assertEqual(User.objects.get(email='ravi@gmail.com').role, 'ADMIN')

    def test_team_leader_with_correct_code(self):
        self.assertRedirects(self.post_signup('TEAM_LEADER', 'Leader-Code-2026'), reverse('accounts:login'))
        self.assertEqual(User.objects.get(email='ravi@gmail.com').role, 'TEAM_LEADER')

    def test_admin_without_code_is_refused(self):
        response = self.post_signup('ADMIN')
        self.assertContains(response, 'Enter the authorization code for the Admin role.')
        self.assertFalse(User.objects.exists())

    def test_admin_with_wrong_code_is_refused_and_audited(self):
        response = self.post_signup('ADMIN', 'guess')
        self.assertContains(response, 'Incorrect authorization code for the Admin role.')
        self.assertFalse(User.objects.exists())
        self.assertTrue(AuditLog.objects.filter(
            action=AuditLog.Action.ACCESS_DENIED, target='signup:role:ADMIN').exists())

    def test_leader_code_does_not_unlock_admin(self):
        self.post_signup('ADMIN', 'Leader-Code-2026')
        self.assertFalse(User.objects.exists())

    @override_settings(SV_ROLE_SIGNUP_CODES={'TEAM_LEADER': '', 'ADMIN': ''})
    def test_privileged_roles_disabled_when_no_code_configured(self):
        response = self.post_signup('ADMIN', 'anything')
        self.assertContains(response, 'Admin accounts cannot be created by sign-up.')

    def test_invalid_role_value_rejected(self):
        response = self.post_signup('SUPERUSER')
        self.assertContains(response, 'Please choose a valid role.')


class PrivilegeTests(TestCase):
    def test_role_privileges(self):
        employee = make_user(role='EMPLOYEE')
        leader = make_user(email='lead@gmail.com', username='lead', role='TEAM_LEADER')
        admin = make_user(email='boss@gmail.com', username='boss', role='ADMIN')
        self.assertTrue(employee.has_privilege(Privilege.USE_CHAT))
        self.assertFalse(employee.has_privilege(Privilege.POST_TEAM_ANNOUNCEMENTS))
        self.assertFalse(employee.has_privilege(Privilege.MANAGE_USERS))
        self.assertTrue(leader.has_privilege(Privilege.POST_TEAM_ANNOUNCEMENTS))
        self.assertFalse(leader.has_privilege(Privilege.MANAGE_USERS))
        self.assertTrue(admin.has_privilege(Privilege.MANAGE_USERS))
        self.assertTrue(admin.has_privilege(Privilege.RUN_FORENSICS))

    def test_inactive_user_has_no_privileges(self):
        user = make_user(role='ADMIN', is_active=False)
        self.assertEqual(user.privileges, frozenset())

    def test_profile_lists_privileges(self):
        make_user(role='TEAM_LEADER')
        self.client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})
        page = self.client.get(reverse('accounts:profile'))
        self.assertContains(page, 'Your privileges')
        self.assertContains(page, 'Post team announcements')
        self.assertNotContains(page, 'Manage users and roles')


class UserManagementTests(TestCase):
    def setUp(self):
        self.admin = make_user(email='boss@gmail.com', username='boss', full_name='Boss Admin', role='ADMIN')
        self.employee = make_user(email='emp@gmail.com', username='emp', full_name='Emp One')
        self.admin_client = Client()
        self.admin_client.post(reverse('accounts:login'), {'email': 'boss@gmail.com', 'password': STRONG})
        self.emp_client = Client()
        self.emp_client.post(reverse('accounts:login'), {'email': 'emp@gmail.com', 'password': STRONG})

    def test_employee_is_blocked_server_side_and_audited(self):
        self.assertEqual(self.emp_client.get(reverse('accounts:user_list')).status_code, 403)
        response = self.emp_client.post(reverse('accounts:user_set_role', args=[self.employee.pk]),
                                        {'role': 'ADMIN'})
        self.assertEqual(response.status_code, 403)
        self.employee.refresh_from_db()
        self.assertEqual(self.employee.role, 'EMPLOYEE')
        self.assertTrue(AuditLog.objects.filter(
            user=self.employee, action=AuditLog.Action.ACCESS_DENIED).exists())

    def test_sidebar_link_only_for_admin(self):
        self.assertContains(self.admin_client.get(reverse('core:dashboard')), 'User Management')
        self.assertNotContains(self.emp_client.get(reverse('core:dashboard')), 'User Management')

    def test_admin_sees_real_users(self):
        page = self.admin_client.get(reverse('accounts:user_list'))
        self.assertContains(page, 'emp@gmail.com')
        self.assertContains(page, 'boss@gmail.com')
        filtered = self.admin_client.get(reverse('accounts:user_list'), {'q': 'emp'})
        self.assertNotContains(filtered, 'boss@gmail.com</span>')

    def test_admin_changes_role_and_it_applies_immediately(self):
        self.admin_client.post(reverse('accounts:user_set_role', args=[self.employee.pk]),
                               {'role': 'TEAM_LEADER'})
        self.employee.refresh_from_db()
        self.assertEqual(self.employee.role, 'TEAM_LEADER')
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.PERMISSION_CHANGED).exists())
        page = self.emp_client.get(reverse('accounts:profile'))
        self.assertContains(page, 'Team Leader')

    def test_admin_cannot_change_own_role(self):
        self.admin_client.post(reverse('accounts:user_set_role', args=[self.admin.pk]), {'role': 'EMPLOYEE'})
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, 'ADMIN')

    def test_deactivate_signs_user_out_everywhere(self):
        self.admin_client.post(reverse('accounts:user_set_status', args=[self.employee.pk]),
                               {'action': 'deactivate'})
        self.employee.refresh_from_db()
        self.assertFalse(self.employee.is_active)
        self.assertEqual(self.emp_client.get(reverse('core:dashboard')).status_code, 302)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.USER_REMOVED).exists())
        self.admin_client.post(reverse('accounts:user_set_status', args=[self.employee.pk]),
                               {'action': 'activate'})
        self.employee.refresh_from_db()
        self.assertTrue(self.employee.is_active)

    def test_admin_can_demote_another_admin_when_two_exist(self):
        other_admin = make_user(email='admin2@gmail.com', username='admin2', role='ADMIN')
        other_client = Client()
        other_client.post(reverse('accounts:login'), {'email': 'admin2@gmail.com', 'password': STRONG})
        other_client.post(reverse('accounts:user_set_role', args=[self.admin.pk]), {'role': 'EMPLOYEE'})
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, 'EMPLOYEE')
        self.assertTrue(other_admin.has_privilege(Privilege.MANAGE_USERS))