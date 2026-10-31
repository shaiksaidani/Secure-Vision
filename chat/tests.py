"""Phase 4 tests (chat): run with  python manage.py test"""
import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog
from teams.models import Team, TeamMembership

from .models import Conversation, Message

User = get_user_model()
STRONG = 'Secure@123'


def make_user(email, username, full_name, role='EMPLOYEE'):
    return User.objects.create_user(email=email, username=username, password=STRONG,
                                    full_name=full_name, role=role)


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


@override_settings(SV_CHAT_POLICY='team')
class ChatTests(TestCase):
    def setUp(self):
        self.admin = make_user('boss@gmail.com', 'boss', 'Boss Admin', role='ADMIN')
        self.leader = make_user('lead@gmail.com', 'lead', 'Lena Lead', role='TEAM_LEADER')
        self.alice = make_user('alice@gmail.com', 'alice', 'Alice Rao')
        self.bob = make_user('bob@gmail.com', 'bob', 'Bob Khan')
        self.carol = make_user('carol@gmail.com', 'carol', 'Carol Das')    # other team
        self.alpha = Team.objects.create(name='Team Alpha', leader=self.leader)
        self.beta = Team.objects.create(name='Team Beta')
        for person in (self.leader, self.alice, self.bob):
            TeamMembership.objects.create(team=self.alpha, user=person)
        TeamMembership.objects.create(team=self.beta, user=self.carol)
        self.alice_client = signed_in('alice@gmail.com')
        self.bob_client = signed_in('bob@gmail.com')
        self.carol_client = signed_in('carol@gmail.com')

    # ---- who appears ---------------------------------------------------------
    def test_registered_teammates_and_admins_are_listed(self):
        page = self.alice_client.get(reverse('chat:home'))
        self.assertContains(page, 'Bob Khan')        # same team
        self.assertContains(page, 'Lena Lead')       # same team
        self.assertContains(page, 'Boss Admin')      # admins are always reachable
        self.assertNotContains(page, 'Carol Das')    # different team
        self.assertContains(page, 'Team Alpha')      # community
        self.assertNotContains(page, 'Team Beta')

    @override_settings(SV_CHAT_POLICY='organization')
    def test_organization_policy_lists_everyone(self):
        self.assertContains(self.alice_client.get(reverse('chat:home')), 'Carol Das')

    def test_cannot_start_chat_outside_policy(self):
        self.alice_client.post(reverse('chat:start', args=[self.carol.pk]))
        self.assertFalse(Conversation.objects.filter(kind=Conversation.Kind.DIRECT).exists())
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.ACCESS_DENIED).exists())

    # ---- the CHAT TEST from the requirements --------------------------------
    def test_message_reaches_real_user_and_persists(self):
        response = self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get(direct_key=Conversation.key_for(self.alice, self.bob))
        self.assertRedirects(response, reverse('chat:conversation', args=[conversation.public_id]))

        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]),
                               {'body': 'Hello Bob, the report is ready.'})
        self.assertEqual(Message.objects.get().sender, self.alice)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.CHAT_MESSAGE).exists())

        bob_home = self.bob_client.get(reverse('chat:home'))
        self.assertContains(bob_home, 'Alice Rao')            # conversation listed for Bob
        self.assertContains(bob_home, 'class="unread"')       # with an unread badge
        for _ in range(2):                                    # open, then "refresh"
            page = self.bob_client.get(reverse('chat:conversation', args=[conversation.public_id]))
            self.assertContains(page, 'Hello Bob, the report is ready.')

    def test_existing_partner_listed_once(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        page = self.alice_client.get(reverse('chat:home'))
        self.assertNotContains(page, reverse('chat:start', args=[self.bob.pk]))   # not under "Start"
        self.assertContains(page, reverse('chat:start', args=[self.leader.pk]))

    def test_same_pair_shares_one_conversation(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        self.bob_client.post(reverse('chat:start', args=[self.alice.pk]))
        self.assertEqual(Conversation.objects.filter(kind=Conversation.Kind.DIRECT).count(), 1)

    def test_outsider_cannot_read_or_send(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        self.assertEqual(self.carol_client.get(
            reverse('chat:conversation', args=[conversation.public_id])).status_code, 404)
        self.assertEqual(self.carol_client.post(
            reverse('chat:send', args=[conversation.public_id]), {'body': 'hi'}).status_code, 404)
        self.assertFalse(Message.objects.exists())

    def test_empty_message_rejected(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        response = self.alice_client.post(reverse('chat:send', args=[conversation.public_id]),
                                          {'body': '   '}, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Message.objects.exists())

    def test_message_text_is_escaped(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]),
                               {'body': '<script>alert(1)</script>'})
        page = self.bob_client.get(reverse('chat:conversation', args=[conversation.public_id]))
        self.assertNotContains(page, '<script>alert(1)</script>')
        self.assertContains(page, '&lt;script&gt;alert(1)&lt;/script&gt;')

    # ---- deletion (hover bug) ------------------------------------------------
    def test_viewing_never_deletes_and_delete_needs_post(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]), {'body': 'Keep me'})
        message = Message.objects.get()
        for _ in range(3):
            self.bob_client.get(reverse('chat:conversation', args=[conversation.public_id]))
            self.alice_client.get(reverse('chat:updates', args=[conversation.public_id]))
        self.assertEqual(self.alice_client.get(reverse('chat:delete', args=[message.pk])).status_code, 405)
        message.refresh_from_db()
        self.assertFalse(message.is_deleted)

    def test_sender_soft_deletes_and_it_is_audited(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]), {'body': 'Oops'})
        message = Message.objects.get()

        self.bob_client.post(reverse('chat:delete', args=[message.pk]))   # not the sender
        message.refresh_from_db()
        self.assertFalse(message.is_deleted)

        self.alice_client.post(reverse('chat:delete', args=[message.pk]))
        message.refresh_from_db()
        self.assertTrue(message.is_deleted)                       # record kept, flagged
        self.assertEqual(Message.objects.count(), 1)
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action=AuditLog.Action.MESSAGE_DELETE).exists())
        page = self.bob_client.get(reverse('chat:conversation', args=[conversation.public_id]))
        self.assertContains(page, 'Message deleted')
        self.assertNotContains(page, 'Oops')

    # ---- live updates --------------------------------------------------------
    def test_updates_endpoint_returns_new_messages(self):
        self.alice_client.post(reverse('chat:start', args=[self.bob.pk]))
        conversation = Conversation.objects.get()
        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]), {'body': 'First'})
        first = Message.objects.get()
        self.alice_client.post(reverse('chat:send', args=[conversation.public_id]), {'body': 'Second'})
        data = json.loads(self.bob_client.get(
            reverse('chat:updates', args=[conversation.public_id]), {'after': first.pk}).content)
        self.assertEqual([m['body'] for m in data['messages']], ['Second'])
        self.assertFalse(data['messages'][0]['mine'])

    # ---- team community ------------------------------------------------------
    def test_team_community_membership_and_announcements(self):
        response = self.alice_client.get(reverse('chat:team', args=[self.alpha.pk]))
        community = Conversation.objects.get(team=self.alpha)
        self.assertRedirects(response, reverse('chat:conversation', args=[community.public_id]))

        self.assertEqual(self.carol_client.get(reverse('chat:team', args=[self.alpha.pk])).status_code, 404)
        self.assertEqual(self.carol_client.get(
            reverse('chat:conversation', args=[community.public_id])).status_code, 404)

        leader_client = signed_in('lead@gmail.com')
        leader_client.post(reverse('chat:send', args=[community.public_id]),
                           {'body': "Tomorrow's meeting is at 10 AM.", 'announcement': 'on'})
        self.alice_client.post(reverse('chat:send', args=[community.public_id]),
                               {'body': 'Noted', 'announcement': 'on'})
        self.assertTrue(Message.objects.get(sender=self.leader).is_announcement)
        self.assertFalse(Message.objects.get(sender=self.alice).is_announcement)   # employees can't announce
        page = self.bob_client.get(reverse('chat:conversation', args=[community.public_id]))
        self.assertContains(page, 'meeting is at 10 AM.')
        self.assertContains(page, 'Announcement')