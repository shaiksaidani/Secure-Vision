"""Phase 9 tests (security headers, deployment checks, navigation): python manage.py test"""
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from teams.models import Team, TeamMembership
from vault.models import ProtectedFile

from .checks import securevision_deploy_checks

User = get_user_model()
STRONG = 'Secure@123'
STORAGE = tempfile.mkdtemp(prefix='sv-test-core-')


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_PROTECTED_STORAGE=STORAGE)
class SecurityHeaderTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(STORAGE, ignore_errors=True)

    def setUp(self):
        User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                 full_name='Boss Admin', role='ADMIN')
        User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                 full_name='Alice Rao')
        self.admin = signed_in('boss@gmail.com')
        self.alice = signed_in('alice@gmail.com')

    def test_pages_carry_csp_and_are_not_cached(self):
        page = self.alice.get(reverse('core:dashboard'))
        csp = page['Content-Security-Policy']
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn('no-store', page['Cache-Control'])
        self.assertIn('camera=()', page['Permissions-Policy'])
        self.assertIn('Content-Security-Policy', Client().get(reverse('accounts:login')))

    def test_no_inline_script_or_style_attributes(self):
        for client, name in ((self.alice, 'core:dashboard'), (self.admin, 'security:center'),
                             (self.admin, 'reports:summary')):
            html = client.get(reverse(name)).content.decode('utf-8')
            self.assertNotIn('onclick=', html)
            self.assertNotIn(' style="', html)
            self.assertNotIn('<script>', html)

    def test_protected_file_content_is_not_given_page_csp(self):
        team = Team.objects.create(name='Team Alpha')
        TeamMembership.objects.create(team=team, user=User.objects.get(email='alice@gmail.com'))
        self.admin.post(reverse('vault:hub'), {'file': SimpleUploadedFile('plan.pdf', b'%PDF-1.4\n%%EOF\n'),
                                               'allowed_teams': [team.pk]})
        item = ProtectedFile.objects.get()
        content = self.alice.get(reverse('vault:content', args=[item.public_id]))
        self.assertEqual(content.status_code, 200)
        self.assertNotIn('Content-Security-Policy', content)       # Chrome's PDF viewer keeps working
        viewer = self.alice.get(reverse('vault:viewer', args=[item.public_id]))
        self.assertIn("frame-src 'self'", viewer['Content-Security-Policy'])


class DeploymentCheckTests(TestCase):

    @override_settings(SV_ROLE_SIGNUP_CODES={'ADMIN': 'Admin#SV-9Xp4', 'TEAM_LEADER': ''},
                       SV_FILE_ENCRYPTION_KEY='', SECURE_COOKIES=False, SV_REVEAL_UNKNOWN_EMAIL=True)
    def test_unsafe_settings_are_reported(self):
        ids = {problem.id for problem in securevision_deploy_checks()}
        self.assertTrue({'securevision.E001', 'securevision.E002', 'securevision.W001',
                         'securevision.W004'} <= ids)

    @override_settings(SV_ROLE_SIGNUP_CODES={'ADMIN': 'k3P!vQ9#zT2mW8xR', 'TEAM_LEADER': ''},
                       SV_FILE_ENCRYPTION_KEY='a-real-key', SECURE_COOKIES=True, SV_REVEAL_UNKNOWN_EMAIL=False)
    def test_safe_settings_pass(self):
        ids = {problem.id for problem in securevision_deploy_checks()}
        self.assertFalse({'securevision.E001', 'securevision.E002', 'securevision.W001',
                          'securevision.W004'} & ids)


class NavigationTests(TestCase):
    def setUp(self):
        User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                 full_name='Boss Admin', role='ADMIN')
        User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                 full_name='Alice Rao')

    def test_sidebar_is_grouped_by_role(self):
        admin_page = signed_in('boss@gmail.com').get(reverse('core:dashboard'))
        for heading in ('Workspace', 'Administration', 'Security', 'Account'):
            self.assertContains(admin_page, '>{}</p>'.format(heading))
        self.assertContains(admin_page, 'Open security alerts')

        employee_page = signed_in('alice@gmail.com').get(reverse('core:dashboard'))
        self.assertContains(employee_page, '>Workspace</p>')
        self.assertNotContains(employee_page, '>Administration</p>')
        self.assertNotContains(employee_page, '>Security</p>')
        self.assertNotContains(employee_page, 'Open security alerts')code 