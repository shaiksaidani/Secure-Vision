"""Phase 7 tests (Access Requests): python manage.py test"""
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog
from notifications.models import Notification
from teams.models import Team, TeamMembership

from .models import AccessRequest, ProtectedFile

User = get_user_model()
STRONG = 'Secure@123'
PDF = b'%PDF-1.4\n% confidential\n%%EOF\n'
STORAGE = tempfile.mkdtemp(prefix='sv-test-requests-')


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_PROTECTED_STORAGE=STORAGE)
class AccessRequestTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(STORAGE, ignore_errors=True)

    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.bob = User.objects.create_user(email='bob@gmail.com', username='bob', password=STRONG,
                                            full_name='Bob Khan')
        beta = Team.objects.create(name='Team Beta')
        self.admin_client = signed_in('boss@gmail.com')
        self.admin_client.post(reverse('vault:hub'), {'file': SimpleUploadedFile('confidential.pdf', PDF),
                                                      'allowed_teams': [beta.pk]})
        self.file = ProtectedFile.objects.get()
        self.bob_client = signed_in('bob@gmail.com')
        self.viewer = reverse('vault:viewer', args=[self.file.public_id])

    def request_access(self, reason='Needed for the quarterly audit'):
        return self.bob_client.post(reverse('vault:request_access', args=[self.file.public_id]),
                                    {'reason': reason}, follow=True)

    def test_restricted_page_offers_request_and_admin_is_told(self):
        page = self.bob_client.get(self.viewer)
        self.assertContains(page, 'Request access', status_code=403)
        self.request_access()
        item = AccessRequest.objects.get()
        self.assertEqual(item.status, AccessRequest.Status.PENDING)
        self.assertTrue(AuditLog.objects.filter(user=self.bob, action=AuditLog.Action.ACCESS_REQUEST).exists())
        self.assertTrue(Notification.objects.filter(user=self.admin, kind=Notification.Kind.REQUEST).exists())
        self.assertContains(self.bob_client.get(self.viewer), 'waiting for review', status_code=403)

    def test_no_duplicate_pending_requests(self):
        self.request_access()
        self.request_access()
        self.assertEqual(AccessRequest.objects.count(), 1)

    def test_approve_grants_access_and_notifies(self):
        self.request_access()
        item = AccessRequest.objects.get()
        self.admin_client.post(reverse('vault:decide', args=[item.public_id]), {'decision': 'approve'})
        item.refresh_from_db()
        self.assertEqual(item.status, AccessRequest.Status.APPROVED)
        self.assertEqual(self.bob_client.get(reverse('vault:content', args=[self.file.public_id])).status_code, 200)
        self.assertTrue(Notification.objects.filter(
            user=self.bob, title='You have been granted access to "confidential.pdf"').exists())
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ACCESS_APPROVED).exists())

    def test_reject_keeps_file_closed(self):
        self.request_access()
        item = AccessRequest.objects.get()
        self.admin_client.post(reverse('vault:decide', args=[item.public_id]),
                               {'decision': 'reject', 'note': 'Not part of your project'})
        item.refresh_from_db()
        self.assertEqual(item.status, AccessRequest.Status.REJECTED)
        self.assertEqual(self.bob_client.get(reverse('vault:content', args=[self.file.public_id])).status_code, 403)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.ACCESS_REJECTED).exists())

    def test_employee_cannot_decide(self):
        self.request_access()
        item = AccessRequest.objects.get()
        response = self.bob_client.post(reverse('vault:decide', args=[item.public_id]), {'decision': 'approve'})
        self.assertEqual(response.status_code, 403)
        item.refresh_from_db()
        self.assertEqual(item.status, AccessRequest.Status.PENDING)

    def test_request_needs_a_reason(self):
        self.request_access(reason='')
        self.assertFalse(AccessRequest.objects.exists())