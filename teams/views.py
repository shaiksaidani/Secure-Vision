"""Teams: admins create teams, choose leaders and assign members; everyone
else sees only the teams they belong to. All checks run on the server."""
from django.contrib import messages
from django.db import transaction
from django.db.models import Count
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event

from .forms import AddMembersForm, TeamForm
from .models import Team, TeamMembership

Action = AuditLog.Action


def _team_snapshot(team):
    return {
        'name': team.name,
        'description': team.description,
        'leader': team.leader.email if team.leader_id else None,
    }


def _ensure_member(team, user, added_by):
    """Add user to team if not already a member. Returns True if added."""
    _membership, created = TeamMembership.objects.get_or_create(
        team=team, user=user, defaults={'added_by': added_by})
    return created


def _visible_teams(user):
    """MANAGE_TEAMS holders see every team; everyone else only their own."""
    teams = (Team.objects.select_related('leader')
             .annotate(member_count=Count('memberships', distinct=True)))
    if user.has_privilege(Privilege.MANAGE_TEAMS):
        return teams
    my_team_ids = TeamMembership.objects.filter(user=user).values('team_id')
    return teams.filter(pk__in=my_team_ids)


def _get_visible_team_or_404(request, pk):
    team = get_object_or_404(Team.objects.select_related('leader', 'created_by'), pk=pk)
    if request.user.has_privilege(Privilege.MANAGE_TEAMS) or team.has_member(request.user):
        return team
    # Not a member: record the attempt, and don't reveal that the team exists.
    log_event(Action.ACCESS_DENIED, request=request, target='team:{}'.format(team.pk),
              result=AuditLog.Result.DENIED, details={'reason': 'not_a_team_member'})
    raise Http404('Team not found')


def _names(users):
    names = [u.full_name for u in users]
    if len(names) <= 3:
        return ', '.join(names)
    return '{} and {} more'.format(', '.join(names[:3]), len(names) - 3)


@privilege_required(Privilege.VIEW_OWN_TEAM)
def team_list_view(request):
    can_manage = request.user.has_privilege(Privilege.MANAGE_TEAMS)
    my_team_ids = set(TeamMembership.objects.filter(user=request.user)
                      .values_list('team_id', flat=True))
    return render(request, 'teams/team_list.html', {
        'teams': _visible_teams(request.user),
        'can_manage': can_manage,
        'my_team_ids': my_team_ids,
    })


@privilege_required(Privilege.VIEW_OWN_TEAM)
def team_detail_view(request, pk):
    team = _get_visible_team_or_404(request, pk)
    can_manage = request.user.has_privilege(Privilege.MANAGE_TEAMS)
    memberships = team.memberships.select_related('user').order_by('user__full_name')
    return render(request, 'teams/team_detail.html', {
        'team': team,
        'memberships': memberships,
        'can_manage': can_manage,
        'add_form': AddMembersForm(team) if can_manage else None,
    })


@privilege_required(Privilege.MANAGE_TEAMS)
def team_create_view(request):
    form = TeamForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            team = form.save(commit=False)
            team.created_by = request.user
            team.save()
            if team.leader_id:
                _ensure_member(team, team.leader, request.user)
        log_event(Action.TEAM_CREATED, request=request, target='team:{}'.format(team.pk),
                  details=_team_snapshot(team))
        messages.success(request, 'Team "{}" created. Now add its members.'.format(team.name))
        return redirect('teams:detail', pk=team.pk)
    return render(request, 'teams/team_form.html', {'form': form, 'team': None})


@privilege_required(Privilege.MANAGE_TEAMS)
def team_edit_view(request, pk):
    team = get_object_or_404(Team, pk=pk)
    team_name = team.name
    before = _team_snapshot(team)
    form = TeamForm(request.POST or None, instance=team)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            team = form.save()
            if team.leader_id:
                _ensure_member(team, team.leader, request.user)
        after = _team_snapshot(team)
        changes = {key: [before[key], after[key]] for key in before if before[key] != after[key]}
        if changes:
            log_event(Action.TEAM_UPDATED, request=request, target='team:{}'.format(team.pk),
                      details=changes)
            messages.success(request, 'Team "{}" updated.'.format(team.name))
        else:
            messages.info(request, 'No changes to save.')
        return redirect('teams:detail', pk=team.pk)
    return render(request, 'teams/team_form.html', {'form': form, 'team': team, 'team_name': team_name})


@privilege_required(Privilege.MANAGE_TEAMS)
@require_POST
def team_add_members_view(request, pk):
    team = get_object_or_404(Team, pk=pk)
    form = AddMembersForm(team, request.POST)
    if form.is_valid():
        added = []
        with transaction.atomic():
            for user in form.cleaned_data['users']:
                if _ensure_member(team, user, request.user):
                    added.append(user)
        for user in added:
            log_event(Action.TEAM_MEMBER_ADDED, request=request, target='team:{}'.format(team.pk),
                      details={'team': team.name, 'member': user.email})
        if added:
            messages.success(request, 'Added {} to {}.'.format(_names(added), team.name))
    else:
        for error in form.errors.get('users', []):
            messages.error(request, error)
    return redirect('teams:detail', pk=team.pk)


@privilege_required(Privilege.MANAGE_TEAMS)
@require_POST
def team_remove_member_view(request, pk, user_pk):
    team = get_object_or_404(Team, pk=pk)
    membership = get_object_or_404(TeamMembership.objects.select_related('user'),
                                   team=team, user_id=user_pk)
    member = membership.user
    was_leader = team.leader_id == member.pk
    with transaction.atomic():
        membership.delete()
        if was_leader:
            team.leader = None
            team.save(update_fields=['leader', 'updated_at'])
    log_event(Action.TEAM_MEMBER_REMOVED, request=request, target='team:{}'.format(team.pk),
              details={'team': team.name, 'member': member.email, 'was_leader': was_leader})
    message = '{} removed from {}.'.format(member.full_name, team.name)
    if was_leader:
        message += ' The team no longer has a leader.'
    messages.success(request, message)
    return redirect('teams:detail', pk=team.pk)