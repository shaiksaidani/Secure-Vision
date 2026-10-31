"""Phase 6 tests (watermarking, tamper detection, Forensic Analyzer):
run with  python manage.py test"""
import io
import random
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from PIL import Image, ImageDraw

from audit.models import AuditLog
from teams.models import Team, TeamMembership
from vault.models import ProtectedFile

from . import watermark as wm
from .models import ForensicAnalysis, Watermark

User = get_user_model()
STRONG = 'Secure@123'
TEMP_STORAGE = tempfile.mkdtemp(prefix='sv-test-forensics-')
PDF_BYTES = b'%PDF-1.4\n% Quarterly plan\n1 0 obj << >> endobj\n%%EOF\n'


def picture(seed=1, size=(320, 240), fmt='PNG'):
    rng = random.Random(seed)
    image = Image.new('RGB', size, (20, 40, 60))
    draw = ImageDraw.Draw(image)
    for _ in range(30):
        x, y = rng.randrange(size[0]), rng.randrange(size[1])
        draw.rectangle([x, y, x + rng.randrange(10, 120), y + rng.randrange(10, 120)],
                       fill=(rng.randrange(256), rng.randrange(256), rng.randrange(256)))
    output = io.BytesIO()
    image.save(output, fmt)
    return output.getvalue()


def reencode(data, fmt, **options):
    output = io.BytesIO()
    Image.open(io.BytesIO(data)).convert('RGB').save(output, fmt, **options)
    return output.getvalue()


def crop(data, box):
    output = io.BytesIO()
    Image.open(io.BytesIO(data)).crop(box).save(output, 'PNG')
    return output.getvalue()


class WatermarkAlgorithmTests(SimpleTestCase):
    def test_round_trip_and_crop(self):
        marked = wm.embed(picture(), 0xABCDEF123456)
        self.assertEqual(wm.extract(marked)[0], 0xABCDEF123456)
        self.assertEqual(wm.extract(crop(marked, (13, 7, 250, 190)))[0], 0xABCDEF123456)
        self.assertEqual(wm.extract(reencode(marked, 'BMP'))[0], 0xABCDEF123456)

    def test_invisible(self):
        original = Image.open(io.BytesIO(picture())).convert('RGB')
        marked = Image.open(io.BytesIO(wm.embed(picture(), 99))).convert('RGB')
        for before, after in zip(original.getdata(), marked.getdata()):
            self.assertLessEqual(max(abs(a - b) for a, b in zip(before, after)), 1)

    def test_not_claimed_when_absent_or_destroyed(self):
        self.assertIsNone(wm.extract(picture(seed=5)))
        self.assertIsNone(wm.extract(reencode(wm.embed(picture(), 7), 'JPEG', quality=95)))
        self.assertIsNone(wm.extract(b'not an image'))


@override_settings(SV_PROTECTED_STORAGE=TEMP_STORAGE)
class ForensicFlowTests(TestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(TEMP_STORAGE, ignore_errors=True)

    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                              full_name='Alice Rao')
        team = Team.objects.create(name='Team Alpha')
        TeamMembership.objects.create(team=team, user=self.alice)
        self.team = team
        self.admin_client = Client()
        self.admin_client.post(reverse('accounts:login'), {'email': 'boss@gmail.com', 'password': STRONG})
        self.alice_client = Client()
        self.alice_client.post(reverse('accounts:login'), {'email': 'alice@gmail.com', 'password': STRONG})

    def upload(self, name, data, **extra):
        payload = {'file': SimpleUploadedFile(name, data), 'title': '', 'description': '',
                   'allowed_teams': [self.team.pk], 'visible_watermark': 'on', 'forensic_watermark': 'on'}
        payload.update(extra)
        self.admin_client.post(reverse('vault:hub'), payload)
        return ProtectedFile.objects.get(original_filename=name)

    def analyse(self, name, data):
        self.admin_client.post(reverse('forensics:analyzer'), {'sample': SimpleUploadedFile(name, data)})
        return ForensicAnalysis.objects.order_by('-created_at').first()

    # ---- personalised copies ---------------------------------------------------
    def test_each_view_is_a_copy_marked_to_the_viewer(self):
        original = picture(seed=3)
        photo = self.upload('site-plan.png', original)
        self.assertTrue(photo.perceptual_hash)
        served = self.alice_client.get(reverse('vault:content', args=[photo.public_id]))
        self.assertEqual(served['Content-Type'], 'image/png')
        self.assertNotEqual(served.content, original)
        code, _confidence = wm.extract(served.content)
        mark = Watermark.objects.get(code='{:012x}'.format(code))
        self.assertEqual(mark.recipient, self.alice)
        self.assertEqual(mark.purpose, Watermark.Purpose.VIEW)
        self.alice_client.get(reverse('vault:content', args=[photo.public_id]))
        self.assertEqual(Watermark.objects.filter(recipient=self.alice).count(), 1)   # same day, same mark

    def test_downloads_are_marked_png_copies(self):
        photo = self.upload('photo.jpg', picture(seed=4, fmt='JPEG'), allow_download='on')
        response = self.alice_client.get(reverse('vault:download', args=[photo.public_id]))
        self.assertIn('photo.png', response['Content-Disposition'])
        code, _confidence = wm.extract(response.content)
        self.assertEqual(Watermark.objects.get(code='{:012x}'.format(code)).purpose, Watermark.Purpose.DOWNLOAD)

    def test_forensic_watermark_can_be_switched_off(self):
        original = picture(seed=6)
        photo = self.upload('plain.png', original, forensic_watermark='')
        served = self.alice_client.get(reverse('vault:content', args=[photo.public_id]))
        self.assertEqual(served.content, original)
        self.assertFalse(Watermark.objects.exists())

    # ---- the FORENSIC analysis -------------------------------------------------
    def test_leaked_copy_identifies_the_recipient(self):
        photo = self.upload('design.png', picture(seed=7))
        leaked = self.alice_client.get(reverse('vault:content', args=[photo.public_id])).content
        analysis = self.analyse('found-online.png', leaked)
        self.assertEqual(analysis.watermark_status, ForensicAnalysis.WatermarkStatus.FOUND)
        self.assertEqual(analysis.tampered, ForensicAnalysis.Tampered.NOT_DETECTED)
        self.assertEqual(analysis.associated_user, self.alice)
        self.assertEqual(analysis.matched_file, photo)
        self.assertEqual(analysis.risk, ForensicAnalysis.Risk.HIGH)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.FORENSIC_ANALYSIS).exists())
        report = self.admin_client.get(reverse('forensics:report', args=[analysis.public_id]))
        self.assertContains(report, 'alice@gmail.com')
        self.assertContains(report, 'Viewed in the secure viewer')

    def test_cropped_leak_is_traced_and_marked_tampered(self):
        photo = self.upload('design.png', picture(seed=8))
        leaked = self.alice_client.get(reverse('vault:content', args=[photo.public_id])).content
        analysis = self.analyse('cropped.png', crop(leaked, (20, 15, 300, 220)))
        self.assertEqual(analysis.watermark_status, ForensicAnalysis.WatermarkStatus.FOUND)
        self.assertEqual(analysis.tampered, ForensicAnalysis.Tampered.DETECTED)
        self.assertEqual(analysis.associated_user, self.alice)

    def test_recompressed_leak_is_linked_but_not_attributed(self):
        photo = self.upload('design.png', picture(seed=9))
        leaked = self.alice_client.get(reverse('vault:content', args=[photo.public_id])).content
        analysis = self.analyse('blurry.jpg', reencode(leaked, 'JPEG', quality=80))
        self.assertEqual(analysis.watermark_status, ForensicAnalysis.WatermarkStatus.NOT_FOUND)
        self.assertEqual(analysis.matched_file, photo)                 # visually similar
        self.assertEqual(analysis.tampered, ForensicAnalysis.Tampered.DETECTED)
        self.assertIsNone(analysis.associated_user)                    # no guessing
        self.assertEqual(analysis.risk, ForensicAnalysis.Risk.MEDIUM)

    def test_identical_pdf_lists_who_accessed_it(self):
        pdf = self.upload('plan.pdf', PDF_BYTES)
        self.alice_client.get(reverse('vault:content', args=[pdf.public_id]))
        analysis = self.analyse('plan-copy.pdf', PDF_BYTES)
        self.assertEqual(analysis.matched_file, pdf)
        self.assertEqual(analysis.tampered, ForensicAnalysis.Tampered.NOT_DETECTED)
        self.assertEqual(analysis.watermark_status, ForensicAnalysis.WatermarkStatus.NOT_APPLICABLE)
        self.assertEqual(analysis.evidence, ForensicAnalysis.Evidence.AVAILABLE)
        self.assertIn('alice@gmail.com', analysis.details_dict['accessed_by'])

    def test_unrelated_file_is_insufficient_evidence(self):
        analysis = self.analyse('notes.txt', b'nothing to do with SecureVision')
        self.assertIsNone(analysis.matched_file)
        self.assertEqual(analysis.risk, ForensicAnalysis.Risk.LOW)
        self.assertEqual(analysis.evidence, ForensicAnalysis.Evidence.INSUFFICIENT)

    def test_only_authorized_users_can_analyse(self):
        response = self.alice_client.post(reverse('forensics:analyzer'),
                                          {'sample': SimpleUploadedFile('x.txt', b'x')})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ForensicAnalysis.objects.exists())