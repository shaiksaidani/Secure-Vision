"""Phase 7 tests (notifications): python manage.py test"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from teams.models import Team, TeamMembership

from .models import Notification
from .services import notify

User = get_user_model()
STRONG = 'Secure@123'
PDF = b'%PDF-1.4\n% plan\n%%EOF\n'


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


class NotificationTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                              full_name='Alice Rao')
        self.team = Team.objects.create(name='Team Alpha', leader=self.admin)
        TeamMembership.objects.create(team=self.team, user=self.alice)
        TeamMembership.objects.create(team=self.team, user=self.admin)

    def test_bell_open_and_mark_read(self):
        item = notify(self.alice, Notification.Kind.ACCESS, 'Hello Alice', url='/files/')
        client = signed_in('alice@gmail.com')
        self.assertContains(client.get(reverse('core:dashboard')), 'class="bell-count"')
        response = client.get(reverse('notifications:open', args=[item.pk]))
        self.assertRedirects(response, '/files/', fetch_redirect_response=False)
        item.refresh_from_db()
        self.assertTrue(item.is_read)

    def test_only_internal_links_are_followed(self):
        item = notify(self.alice, Notification.Kind.ACCESS, 'Phish', url='//evil.example.com/')
        response = signed_in('alice@gmail.com').get(reverse('notifications:open', args=[item.pk]))
        self.assertRedirects(response, reverse('notifications:list'))

    def test_cannot_open_someone_elses(self):
        item = notify(self.admin, Notification.Kind.SECURITY, 'Admin only')
        self.assertEqual(signed_in('alice@gmail.com').get(
            reverse('notifications:open', args=[item.pk])).status_code, 404)

    def test_mark_all_read(self):
        notify(self.alice, Notification.Kind.ACCESS, 'One')
        notify(self.alice, Notification.Kind.ACCESS, 'Two')
        signed_in('alice@gmail.com').post(reverse('notifications:read_all'))
        self.assertFalse(Notification.objects.filter(user=self.alice, read_at__isnull=True).exists())

    def test_check_in_is_confirmed(self):
        signed_in('alice@gmail.com').post(reverse('attendance:check_in'))
        self.assertTrue(Notification.objects.filter(user=self.alice, kind=Notification.Kind.ATTENDANCE,
                                                    title='Your attendance has been recorded').exists())

    def test_team_announcement_reaches_members(self):
        admin = signed_in('boss@gmail.com')
        community = admin.get(reverse('chat:team', args=[self.team.pk]))['Location']
        public_id = community.rstrip('/').split('/')[-1]
        admin.post(reverse('chat:send', args=[public_id]),
                   {'body': "Tomorrow's meeting is at 10 AM.", 'announcement': 'on'})
        note = Notification.objects.get(user=self.alice, kind=Notification.Kind.ANNOUNCEMENT)
        self.assertIn('Team Alpha', note.title)
        self.assertFalse(Notification.objects.filter(user=self.admin, kind=Notification.Kind.ANNOUNCEMENT).exists())


@override_settings(SV_PROTECTED_STORAGE=__import__('tempfile').mkdtemp(prefix='sv-test-notify-'))
class FileNotificationTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(email='boss@gmail.com', username='boss', password=STRONG,
                                              full_name='Boss Admin', role='ADMIN')
        self.alice = User.objects.create_user(email='alice@gmail.com', username='alice', password=STRONG,
                                              full_name='Alice Rao')
        self.team = Team.objects.create(name='Team Alpha')
        TeamMembership.objects.create(team=self.team, user=self.alice)

    def test_sharing_and_expiry_notifications(self):
        admin = signed_in('boss@gmail.com')
        soon = (timezone.localtime() + timedelta(hours=6)).strftime('%Y-%m-%dT%H:%M')
        admin.post(reverse('vault:hub'), {'file': SimpleUploadedFile('Project.pdf', PDF),
                                          'allowed_teams': [self.team.pk], 'expires_at': soon})
        self.assertTrue(Notification.objects.filter(
            user=self.alice, title='You have been granted access to "Project.pdf"').exists())
        alice = signed_in('alice@gmail.com')
        alice.get(reverse('vault:stored_data'))
        alice.get(reverse('vault:stored_data'))
        self.assertEqual(Notification.objects.filter(user=self.alice, kind=Notification.Kind.EXPIRY).count(), 1)