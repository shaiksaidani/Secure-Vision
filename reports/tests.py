"""Phase 8 tests (Reports): python manage.py test"""
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog
from teams.models import Team, TeamMembership
from vault.models import ProtectedFile

User = get_user_model()
STRONG = 'Secure@123'
STORAGE = tempfile.mkdtemp(prefix='sv-test-reports-')


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_PROTECTED_STORAGE=STORAGE)
class ReportTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(STORAGE, ignore_errors=True)

    def setUp(self):
        User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                 full_name='Boss Admin', role='ADMIN')
        alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                         full_name='Alice Rao')
        team = Team.objects.create(name='Team Alpha')
        TeamMembership.objects.create(team=team, user=alice)
        self.admin = signed_in('boss@gmail.com')
        self.admin.post(reverse('vault:hub'), {'file': SimpleUploadedFile('Budget.pdf', b'%PDF-1.4\n%%EOF\n'),
                                               'allowed_teams': [team.pk]})
        self.file = ProtectedFile.objects.get()
        self.alice = signed_in('alice@gmail.com')
        self.alice.get(reverse('vault:content', args=[self.file.public_id]))

    def test_summary_counts_real_events(self):
        page = self.admin.get(reverse('reports:summary'), {'days': 7})
        sections = dict(page.context['sections'])
        files = dict(sections['Protected files'])
        self.assertEqual(files['Files uploaded'], 1)
        self.assertEqual(files['Files viewed'], 1)
        self.assertContains(page, 'Budget.pdf')                      # most accessed files

    def test_file_access_report_and_csv(self):
        page = self.admin.get(reverse('reports:file_access'))
        row = page.context['rows'][0]
        self.assertEqual((row['views'], row['people']), (1, ['alice@gmail.com']))
        csv_response = self.admin.get(reverse('reports:file_access'), {'export': 'csv'})
        self.assertEqual(csv_response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertIn('Budget.pdf', csv_response.content.decode('utf-8'))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.REPORT_GENERATED).exists())

    def test_reports_are_admin_only(self):
        self.assertEqual(self.alice.get(reverse('reports:summary')).status_code, 403)
        self.assertEqual(self.alice.get(reverse('reports:file_access')).status_code, 403)