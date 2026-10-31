"""Phase 3 tests (protected files): run with  python manage.py test"""
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from teams.models import Team, TeamMembership

from .models import ProtectedFile

User = get_user_model()
STRONG = 'Secure@123'
PDF_BYTES = b'%PDF-1.4\n% SecureVision test document: Quarterly Plan\n1 0 obj << >> endobj\n%%EOF\n'
TEXT_BYTES = 'Project roadmap\nMilestone 1: readable text stays readable.\n'.encode('utf-8')
PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64

TEMP_STORAGE = tempfile.mkdtemp(prefix='sv-test-storage-')


def make_user(email, username, full_name, role='EMPLOYEE'):
    return User.objects.create_user(email=email, username=username, password=STRONG,
                                    full_name=full_name, role=role)


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_PROTECTED_STORAGE=TEMP_STORAGE, SV_MAX_UPLOAD_MB=1)
class ProtectedFileTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(TEMP_STORAGE, ignore_errors=True)

    def setUp(self):
        self.admin = make_user('boss@gmail.com', 'boss', 'Boss Admin', role='ADMIN')
        self.alice = make_user('alice@gmail.com', 'alice', 'Alice Rao')   # Team A
        self.bob = make_user('bob@gmail.com', 'bob', 'Bob Khan')         # Team B
        self.team_a = Team.objects.create(name='Team A')
        self.team_b = Team.objects.create(name='Team B')
        TeamMembership.objects.create(team=self.team_a, user=self.alice)
        TeamMembership.objects.create(team=self.team_b, user=self.bob)
        self.admin_client = signed_in('boss@gmail.com')
        self.alice_client = signed_in('alice@gmail.com')
        self.bob_client = signed_in('bob@gmail.com')

    def upload(self, name='plan.pdf', data=PDF_BYTES, teams=None, users=None, **extra):
        payload = {
            'file': SimpleUploadedFile(name, data),
            'title': extra.pop('title', ''),
            'description': 'Confidential',
            'allowed_teams': [t.pk for t in (teams or [])],
            'allowed_users': [u.pk for u in (users or [])],
            'visible_watermark': 'on',
        }
        payload.update(extra)
        return self.admin_client.post(reverse('vault:hub'), payload)

    # ---- upload ---------------------------------------------------------
    def test_upload_encrypts_at_rest_and_keeps_original_readable(self):
        response = self.upload(teams=[self.team_a])
        self.assertRedirects(response, reverse('vault:hub'))
        f = ProtectedFile.objects.get()
        self.assertEqual(f.title, 'plan.pdf')
        self.assertEqual(f.category, 'PDF')
        stored = (Path(TEMP_STORAGE) / f.storage_name).read_bytes()
        self.assertNotIn(b'Quarterly Plan', stored)            # encrypted on disk
        content = self.alice_client.get(reverse('vault:content', args=[f.public_id]))
        self.assertEqual(content.content, PDF_BYTES)            # original bytes, unchanged
        self.assertEqual(content['Content-Type'], 'application/pdf')
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.FILE_UPLOAD).exists())

    def test_employee_cannot_upload(self):
        response = self.alice_client.post(reverse('vault:hub'), {
            'file': SimpleUploadedFile('x.pdf', PDF_BYTES)})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ProtectedFile.objects.exists())

    def test_rejects_disallowed_type_and_disguised_content(self):
        self.assertContains(self.upload(name='tool.exe', data=b'MZ\x90\x00'), 'This file type is not allowed')
        self.assertContains(self.upload(name='fake.pdf', data=PNG_BYTES), "match its .pdf extension")
        self.assertFalse(ProtectedFile.objects.exists())

    def test_rejects_oversized_file(self):
        response = self.upload(data=b'%PDF-' + b'0' * (1024 * 1024 + 10))
        self.assertContains(response, 'Files must be 1 MB or smaller.')

    def test_rejects_past_expiry(self):
        past = (timezone.localtime() - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M')
        response = self.upload(expires_at=past)
        self.assertContains(response, 'The expiry date must be in the future.')

    def test_upload_form_lists_real_teams_and_people(self):
        page = self.admin_client.get(reverse('vault:hub'))
        self.assertContains(page, 'name="allowed_teams" value="{}"'.format(self.team_a.pk))
        self.assertContains(page, 'name="allowed_users" value="{}"'.format(self.alice.pk))
        self.assertContains(page, 'Alice Rao (alice@gmail.com)')

    # ---- permissions ------------------------------------------------------
    def test_team_a_can_open_team_b_cannot(self):
        self.upload(teams=[self.team_a])
        f = ProtectedFile.objects.get()
        self.assertContains(self.alice_client.get(reverse('vault:stored_data')), 'plan.pdf')
        self.assertNotContains(self.bob_client.get(reverse('vault:stored_data')), 'plan.pdf')
        self.assertEqual(self.alice_client.get(reverse('vault:viewer', args=[f.public_id])).status_code, 200)
        self.assertEqual(self.alice_client.get(reverse('vault:content', args=[f.public_id])).status_code, 200)

        denied = self.bob_client.get(reverse('vault:viewer', args=[f.public_id]))
        self.assertContains(denied, 'You do not have permission to access this file.', status_code=403)
        self.assertEqual(self.bob_client.get(reverse('vault:content', args=[f.public_id])).status_code, 403)
        self.assertTrue(AuditLog.objects.filter(user=self.bob, action=AuditLog.Action.ACCESS_DENIED).exists())
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.FILE_VIEW).exists())

    def test_direct_user_grant(self):
        self.upload(users=[self.bob])
        f = ProtectedFile.objects.get()
        self.assertEqual(self.bob_client.get(reverse('vault:content', args=[f.public_id])).status_code, 200)
        self.assertEqual(self.alice_client.get(reverse('vault:content', args=[f.public_id])).status_code, 403)

    def test_view_only_unless_download_allowed(self):
        self.upload(teams=[self.team_a])
        f = ProtectedFile.objects.get()
        url = reverse('vault:download', args=[f.public_id])
        self.assertContains(self.alice_client.get(url), 'This file can only be viewed in the secure viewer.',
                            status_code=403)
        f.allow_download = True
        f.save()
        response = self.alice_client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertEqual(response.content, PDF_BYTES)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.FILE_DOWNLOAD).exists())

    def test_text_file_is_shown_readable(self):
        self.upload(name='roadmap.txt', data=TEXT_BYTES, teams=[self.team_a])
        f = ProtectedFile.objects.get()
        page = self.alice_client.get(reverse('vault:viewer', args=[f.public_id]))
        self.assertContains(page, 'Milestone 1: readable text stays readable.')
        self.assertContains(page, 'alice@gmail.com')       # visible watermark identity

    # ---- expiry and integrity ---------------------------------------------
    def test_expired_file_is_denied_and_recorded(self):
        self.upload(teams=[self.team_a])
        f = ProtectedFile.objects.get()
        ProtectedFile.objects.filter(pk=f.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        response = self.alice_client.get(reverse('vault:content', args=[f.public_id]))
        self.assertContains(response, 'This file has expired and is no longer available.', status_code=410)
        f.refresh_from_db()
        self.assertEqual(f.status, ProtectedFile.Status.EXPIRED)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.FILE_EXPIRED).exists())

    def test_admin_extends_expiry_and_grants_team_b(self):
        self.upload(teams=[self.team_a])
        f = ProtectedFile.objects.get()
        ProtectedFile.objects.filter(pk=f.pk).update(expires_at=timezone.now() - timedelta(minutes=1),
                                                     status=ProtectedFile.Status.EXPIRED)
        future = (timezone.localtime() + timedelta(days=3)).strftime('%Y-%m-%dT%H:%M')
        self.admin_client.post(reverse('vault:edit', args=[f.public_id]), {
            'title': 'plan.pdf', 'description': '', 'expires_at': future,
            'allowed_teams': [self.team_a.pk, self.team_b.pk], 'visible_watermark': 'on'})
        f.refresh_from_db()
        self.assertEqual(f.status, ProtectedFile.Status.ACTIVE)
        self.assertEqual(self.bob_client.get(reverse('vault:content', args=[f.public_id])).status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.PERMISSION_CHANGED).exists())

    def test_tampered_copy_is_detected(self):
        self.upload(teams=[self.team_a])
        f = ProtectedFile.objects.get()
        (Path(TEMP_STORAGE) / f.storage_name).write_bytes(b'tampered')
        response = self.alice_client.get(reverse('vault:content', args=[f.public_id]))
        self.assertContains(response, 'Integrity check failed', status_code=409)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.INTEGRITY_FAILURE).exists())

    # ---- navigation and dashboard -------------------------------------------
    def test_navigation_and_dashboard_use_real_data(self):
        self.upload(teams=[self.team_a])
        admin_dash = self.admin_client.get(reverse('core:dashboard'))
        self.assertContains(admin_dash, 'DRM Hub')
        self.assertContains(admin_dash, 'Protected files')
        alice_dash = self.alice_client.get(reverse('core:dashboard'))
        self.assertContains(alice_dash, 'Stored Data')
        self.assertNotContains(alice_dash, 'DRM Hub')
        self.assertContains(alice_dash, 'Files available to you')