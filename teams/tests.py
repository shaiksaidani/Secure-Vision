"""Phase 2 tests (Teams): run with  python manage.py test"""
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from audit.models import AuditLog

from .forms import AddMembersForm
from .models import Team, TeamMembership

User = get_user_model()
STRONG = 'Secure@123'


def make_user(email, username, full_name, role='EMPLOYEE', **extra):
    return User.objects.create_user(email=email, username=username, password=STRONG,
                                    full_name=full_name, role=role, **extra)


def signed_in(email):
    client = Client()
    client.post(reverse('accounts:login'), {'email': email, 'password': STRONG})
    return client


class TeamTests(TestCase):
    def setUp(self):
        self.admin = make_user('boss@gmail.com', 'boss', 'Boss Admin', role='ADMIN')
        self.leader = make_user('lead@gmail.com', 'lead', 'Lena Lead', role='TEAM_LEADER')
        self.alice = make_user('alice@gmail.com', 'alice', 'Alice Rao')
        self.bob = make_user('bob@gmail.com', 'bob', 'Bob Khan')
        self.admin_client = signed_in('boss@gmail.com')
        self.alice_client = signed_in('alice@gmail.com')

    def create_team(self, name='Team Alpha', leader=None):
        return self.admin_client.post(reverse('teams:create'), {
            'name': name, 'description': 'Core platform team',
            'leader': leader.pk if leader else ''})

    # ---- creating and editing ------------------------------------------
    def test_admin_creates_team_with_leader_who_becomes_member(self):
        response = self.create_team(leader=self.leader)
        team = Team.objects.get(name='Team Alpha')
        self.assertRedirects(response, reverse('teams:detail', args=[team.pk]))
        self.assertEqual(team.leader, self.leader)
        self.assertEqual(team.created_by, self.admin)
        self.assertTrue(team.has_member(self.leader))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.TEAM_CREATED).exists())

    def test_employee_cannot_create_team(self):
        response = self.alice_client.post(reverse('teams:create'), {'name': 'Rogue'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Team.objects.exists())
        self.assertTrue(AuditLog.objects.filter(
            user=self.alice, action=AuditLog.Action.ACCESS_DENIED).exists())

    def test_duplicate_name_is_case_insensitive(self):
        self.create_team()
        response = self.create_team(name='team alpha')
        self.assertContains(response, 'A team with this name already exists.')
        self.assertEqual(Team.objects.count(), 1)

    def test_employee_cannot_be_leader(self):
        response = self.create_team(leader=self.alice)
        self.assertContains(response, 'Choose an active user with the Team Leader or Admin role.')
        self.assertFalse(Team.objects.exists())

    def test_edit_team_is_audited(self):
        self.create_team()
        team = Team.objects.get()
        self.admin_client.post(reverse('teams:edit', args=[team.pk]), {
            'name': 'Team Alpha One', 'description': 'Renamed', 'leader': self.leader.pk})
        team.refresh_from_db()
        self.assertEqual(team.name, 'Team Alpha One')
        self.assertTrue(team.has_member(self.leader))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.TEAM_UPDATED).exists())

    # ---- members -------------------------------------------------------
    def test_admin_adds_and_removes_members(self):
        self.create_team(leader=self.leader)
        team = Team.objects.get()
        self.admin_client.post(reverse('teams:add_members', args=[team.pk]),
                               {'users': [self.alice.pk, self.bob.pk]})
        self.assertTrue(team.has_member(self.alice))
        self.assertTrue(team.has_member(self.bob))
        self.assertEqual(AuditLog.objects.filter(action=AuditLog.Action.TEAM_MEMBER_ADDED).count(), 2)

        self.admin_client.post(reverse('teams:remove_member', args=[team.pk, self.bob.pk]))
        self.assertFalse(team.has_member(self.bob))
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.TEAM_MEMBER_REMOVED).exists())

    def test_removing_leader_clears_leader(self):
        self.create_team(leader=self.leader)
        team = Team.objects.get()
        self.admin_client.post(reverse('teams:remove_member', args=[team.pk, self.leader.pk]))
        team.refresh_from_db()
        self.assertIsNone(team.leader)

    def test_employee_cannot_add_members(self):
        self.create_team()
        team = Team.objects.get()
        response = self.alice_client.post(reverse('teams:add_members', args=[team.pk]),
                                          {'users': [self.alice.pk]})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(team.has_member(self.alice))

    def test_deactivated_users_and_existing_members_not_offered(self):
        self.create_team(leader=self.leader)
        team = Team.objects.get()
        self.bob.is_active = False
        self.bob.save()
        offered = set(AddMembersForm(team).fields['users'].queryset)
        self.assertIn(self.alice, offered)
        self.assertNotIn(self.bob, offered)          # deactivated
        self.assertNotIn(self.leader, offered)       # already a member

    # ---- visibility ----------------------------------------------------
    def test_employee_sees_only_own_teams(self):
        self.create_team(name='Team Alpha')
        self.create_team(name='Team Beta')
        alpha = Team.objects.get(name='Team Alpha')
        beta = Team.objects.get(name='Team Beta')
        TeamMembership.objects.create(team=alpha, user=self.alice)
        TeamMembership.objects.create(team=alpha, user=self.bob)

        listing = self.alice_client.get(reverse('teams:list'))
        self.assertContains(listing, 'Team Alpha')
        self.assertNotContains(listing, 'Team Beta')

        own = self.alice_client.get(reverse('teams:detail', args=[alpha.pk]))
        self.assertContains(own, 'Bob Khan')                 # sees teammates
        self.assertNotContains(own, 'Add members')           # no admin controls

        other = self.alice_client.get(reverse('teams:detail', args=[beta.pk]))
        self.assertEqual(other.status_code, 404)             # not revealed
        self.assertTrue(AuditLog.objects.filter(
            user=self.alice, action=AuditLog.Action.ACCESS_DENIED,
            target='team:{}'.format(beta.pk)).exists())

    def test_admin_sees_all_teams(self):
        self.create_team(name='Team Alpha')
        self.create_team(name='Team Beta')
        listing = self.admin_client.get(reverse('teams:list'))
        self.assertContains(listing, 'Team Alpha')
        self.assertContains(listing, 'Team Beta')
        self.assertContains(listing, 'Create team')

    def test_profile_shows_real_team(self):
        self.create_team()
        TeamMembership.objects.create(team=Team.objects.get(), user=self.alice)
        profile = self.alice_client.get(reverse('accounts:profile'))
        self.assertContains(profile, 'Team Alpha')
        self.assertNotContains(profile, 'Not assigned yet')

    def test_teams_link_in_sidebar_for_everyone(self):
        self.assertContains(self.alice_client.get(reverse('core:dashboard')), 'Teams')
        self.assertContains(self.admin_client.get(reverse('core:dashboard')), 'Teams')