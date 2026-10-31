"""Teams and team membership.

Every later module (protected files, team chat, attendance) grants access by
team, so these tables are the single source of truth for who is in which team.
"""
from django.conf import settings
from django.db import models


class Team(models.Model):
    name = models.CharField(max_length=80, unique=True,
                            error_messages={'unique': 'A team with this name already exists.'})
    description = models.TextField(blank=True, max_length=500)
    # Must hold the Team Leader or Admin role (enforced in TeamForm).
    leader = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                               on_delete=models.SET_NULL, related_name='led_teams')
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, through='TeamMembership',
                                     through_fields=('team', 'user'),
                                     related_name='teams', blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    def has_member(self, user):
        return self.memberships.filter(user=user).exists()


class TeamMembership(models.Model):
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='team_memberships')
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                 on_delete=models.SET_NULL, related_name='+')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('user__full_name',)
        constraints = [
            models.UniqueConstraint(fields=['team', 'user'], name='unique_team_member'),
        ]

    def __str__(self):
        return '{} in {}'.format(self.user, self.team)