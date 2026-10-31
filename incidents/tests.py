"""Phase 8 tests (Incidents and the Evidence Vault): python manage.py test"""
import json
import shutil
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog
from audit.services import log_event
from forensics.models import ForensicAnalysis
from security.models import SecurityAlert

from .models import CustodyRecord, Evidence, Incident, IncidentEntry

User = get_user_model()
STRONG = 'Secure@123'
STORAGE = tempfile.mkdtemp(prefix='sv-test-incidents-')


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_PROTECTED_STORAGE=STORAGE)
class IncidentTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(STORAGE, ignore_errors=True)

    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                              full_name='Alice Rao')
        self.admin_client = signed_in('boss@gmail.com')

    def open_incident(self, **extra):
        data = {'title': 'Suspicious downloads', 'summary': 'Many downloads overnight.', 'severity': 'HIGH',
                'assigned_to': self.admin.pk, 'subject_user': self.alice.pk}
        data.update(extra)
        query = ''
        if 'alert' in extra:
            query = '?alert={}'.format(extra['alert'])
        self.admin_client.post(reverse('incidents:create') + query, data)
        return Incident.objects.order_by('-created_at').first()

    def upload_evidence(self, incident, content=b'leaked spreadsheet contents'):
        self.admin_client.post(reverse('incidents:evidence_upload', args=[incident.public_id]),
                               {'file': SimpleUploadedFile('leak.csv', content), 'title': 'Leaked copy'})
        return incident.evidence.order_by('-added_at').first()

    # ---- incidents --------------------------------------------------------------
    def test_open_from_alert_links_and_acknowledges_it(self):
        log_event(AuditLog.Action.INTEGRITY_FAILURE, user=self.alice, target='file:abc',
                  result=AuditLog.Result.FAILURE)
        alert = SecurityAlert.objects.get()
        incident = self.open_incident(alert=str(alert.public_id))
        self.assertRegex(incident.reference, r'^INC-\d{4}-0001$')
        self.assertIn(alert, incident.alerts.all())
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.ACKNOWLEDGED)
        kinds = list(incident.entries.values_list('kind', flat=True))
        self.assertEqual(kinds[:2], [IncidentEntry.Kind.CREATED, IncidentEntry.Kind.LINKED])
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.INCIDENT_CREATED).exists())

    def test_status_change_is_recorded_and_closing_sets_time(self):
        incident = self.open_incident()
        self.admin_client.post(reverse('incidents:update', args=[incident.public_id]),
                               {'status': 'RESOLVED', 'severity': 'HIGH', 'assigned_to': self.admin.pk,
                                'note': 'Access revoked and file re-issued.'})
        incident.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.RESOLVED)
        self.assertIsNotNone(incident.closed_at)
        self.assertTrue(incident.entries.filter(kind=IncidentEntry.Kind.STATUS).exists())
        self.assertTrue(incident.entries.filter(kind=IncidentEntry.Kind.NOTE,
                                                text='Access revoked and file re-issued.').exists())

    def test_employee_cannot_see_incidents(self):
        alice = signed_in('alice@gmail.com')
        self.assertEqual(alice.get(reverse('incidents:list')).status_code, 403)
        self.assertEqual(alice.post(reverse('incidents:create'), {'title': 'x', 'severity': 'LOW'}).status_code, 403)
        self.assertFalse(Incident.objects.exists())

    # ---- evidence vault ---------------------------------------------------------
    def test_evidence_is_encrypted_hashed_and_downloadable(self):
        incident = self.open_incident()
        evidence = self.upload_evidence(incident)
        self.assertEqual(evidence.reference, '{}-E01'.format(incident.reference))
        stored = (Path(STORAGE) / evidence.storage_name).read_bytes()
        self.assertNotIn(b'leaked spreadsheet contents', stored)                   # encrypted at rest
        download = self.admin_client.get(reverse('incidents:evidence_download', args=[evidence.public_id]))
        self.assertEqual(download.content, b'leaked spreadsheet contents')        # original bytes back
        actions = list(evidence.custody.values_list('action', flat=True))
        self.assertEqual(actions, [CustodyRecord.Action.ADDED, CustodyRecord.Action.DOWNLOADED])
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.EVIDENCE_ACCESSED).exists())

    def test_tampering_is_detected(self):
        incident = self.open_incident()
        evidence = self.upload_evidence(incident)
        self.admin_client.post(reverse('incidents:evidence_verify', args=[evidence.public_id]))
        (Path(STORAGE) / evidence.storage_name).write_bytes(b'altered')
        self.admin_client.post(reverse('incidents:evidence_verify', args=[evidence.public_id]))
        actions = list(evidence.custody.values_list('action', flat=True))
        self.assertEqual(actions[-2:], [CustodyRecord.Action.VERIFIED, CustodyRecord.Action.VERIFY_FAILED])
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.EVIDENCE_VERIFIED,
                                                result=AuditLog.Result.FAILURE).exists())
        response = self.admin_client.get(reverse('incidents:evidence_download', args=[evidence.public_id]))
        self.assertEqual(response.status_code, 302)                                # refused

    def test_evidence_and_timeline_are_append_only(self):
        incident = self.open_incident()
        evidence = self.upload_evidence(incident)
        evidence.title = 'Changed'
        with self.assertRaises(ValueError):
            evidence.save()
        with self.assertRaises(ValueError):
            evidence.delete()
        entry = incident.entries.first()
        entry.text = 'rewritten'
        with self.assertRaises(ValueError):
            entry.save()
        with self.assertRaises(ValueError):
            evidence.custody.first().delete()

    def test_forensic_sample_becomes_evidence(self):
        self.admin_client.post(reverse('forensics:analyzer'),
                               {'sample': SimpleUploadedFile('found.txt', b'suspicious content')})
        analysis = ForensicAnalysis.objects.get()
        self.admin_client.post(reverse('incidents:create') + '?analysis={}'.format(analysis.public_id),
                               {'title': 'Possible leak', 'severity': 'MEDIUM', 'assigned_to': self.admin.pk,
                                'analysis': str(analysis.public_id)})
        incident = Incident.objects.get()
        evidence = incident.evidence.get()
        self.assertEqual(evidence.kind, Evidence.Kind.FORENSIC_SAMPLE)
        self.assertEqual(evidence.sha256, analysis.sample_sha256)
        self.assertIn(analysis, incident.analyses.all())

    def test_activity_snapshot_captures_the_persons_events(self):
        signed_in('alice@gmail.com').post(reverse('attendance:check_in'))
        incident = self.open_incident()
        self.admin_client.post(reverse('incidents:evidence_snapshot', args=[incident.public_id]))
        evidence = incident.evidence.get(kind=Evidence.Kind.ACTIVITY_SNAPSHOT)
        download = self.admin_client.get(reverse('incidents:evidence_download', args=[evidence.public_id]))
        snapshot = json.loads(download.content.decode('utf-8'))
        actions = {row['action'] for row in snapshot['events']}
        self.assertIn('ATTENDANCE_CHECK_IN', actions)
        self.assertTrue(all(row['account'] == 'alice@gmail.com' for row in snapshot['events']))

    def test_printable_report(self):
        incident = self.open_incident()
        evidence = self.upload_evidence(incident)
        report = self.admin_client.get(reverse('incidents:report', args=[incident.public_id]))
        self.assertContains(report, incident.reference)
        self.assertContains(report, evidence.sha256)
        self.assertContains(report, 'Print / Save as PDF')
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.REPORT_GENERATED).exists())