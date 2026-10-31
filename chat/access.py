"""Who may talk to whom. Every chat view calls these functions.

Policy (SV_CHAT_POLICY in .env):
  team          - people who share a team can message each other; everyone
                  can message administrators, and administrators can
                  message anyone. (default)
  organization  - any active user can message any other active user.
"""
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q

from accounts.permissions import Privilege
from teams.models import Team, TeamMembership

from .models import Conversation, ConversationMember

User = get_user_model()


def _policy():
    return getattr(settings, 'SV_CHAT_POLICY', 'team')


def is_chat_admin(user):
    return user.has_privilege(Privilege.MANAGE_USERS)


def contacts_for(user):
    """Active users this user is allowed to start a direct conversation with."""
    if not user.has_privilege(Privilege.USE_CHAT):
        return User.objects.none()
    people = User.objects.filter(is_active=True).exclude(pk=user.pk)
    if _policy() == 'organization' or is_chat_admin(user):
        return people.order_by('full_name')
    my_teams = TeamMembership.objects.filter(user=user).values('team_id')
    return people.filter(
        Q(role=User.Role.ADMIN) | Q(team_memberships__team_id__in=my_teams)
    ).distinct().order_by('full_name')


def can_message(sender, recipient):
    if recipient is None or not recipient.is_active:
        return False
    return contacts_for(sender).filter(pk=recipient.pk).exists()


def teams_with_community(user):
    """Teams whose community chat the user may open."""
    if user.has_privilege(Privilege.MANAGE_TEAMS):
        return Team.objects.order_by('name')
    return Team.objects.filter(memberships__user=user).order_by('name')


def can_view(user, conversation):
    if not user.has_privilege(Privilege.USE_CHAT):
        return False
    if conversation.kind == Conversation.Kind.TEAM:
        return teams_with_community(user).filter(pk=conversation.team_id).exists()
    return ConversationMember.objects.filter(conversation=conversation, user=user).exists()


def other_participant(user, conversation):
    if conversation.kind != Conversation.Kind.DIRECT:
        return None
    member = (conversation.memberships.exclude(user=user).select_related('user').first())
    return member.user if member else None


def can_post(user, conversation):
    if not can_view(user, conversation):
        return False
    if conversation.kind == Conversation.Kind.DIRECT:
        return can_message(user, other_participant(user, conversation))
    return True


def can_announce(user, conversation):
    """Admins in any community; Team Leaders only in the team they lead."""
    if conversation.kind != Conversation.Kind.TEAM or not can_view(user, conversation):
        return False
    if user.has_privilege(Privilege.MANAGE_TEAMS):
        return True
    return (user.has_privilege(Privilege.POST_TEAM_ANNOUNCEMENTS)
            and conversation.team.leader_id == user.pk)