"""Sidebar navigation and top-bar counters, defined once for every page.

Only modules that actually work are listed. An item with a `privilege` is shown
only to users holding it; the view behind it ALSO enforces it server-side.
"""
from django.urls import reverse

from accounts.permissions import Privilege

NAV_GROUPS = ('Workspace', 'Administration', 'Security', 'Account')

NAV_ITEMS = [
    {'group': 'Workspace', 'label': 'Dashboard', 'url_name': 'core:dashboard', 'icon': 'grid',
     'match': ('core:dashboard',), 'privilege': Privilege.VIEW_DASHBOARD},
    {'group': 'Workspace', 'label': 'Teams', 'url_name': 'teams:list', 'icon': 'team',
     'match': ('teams:list', 'teams:detail', 'teams:create', 'teams:edit'),
     'privilege': Privilege.VIEW_OWN_TEAM},
    {'group': 'Workspace', 'label': 'Stored Data', 'url_name': 'vault:stored_data', 'icon': 'folder',
     'match': ('vault:stored_data', 'vault:viewer'), 'privilege': Privilege.VIEW_AUTHORIZED_FILES},
    {'group': 'Workspace', 'label': 'Attendance', 'url_name': 'attendance:mine', 'icon': 'calendar',
     'match': ('attendance:mine', 'attendance:manage', 'attendance:report'),
     'privilege': Privilege.CHECK_IN_OUT},
    {'group': 'Workspace', 'label': 'Confidential Chat', 'url_name': 'chat:home', 'icon': 'chat',
     'match': ('chat:home', 'chat:conversation'), 'privilege': Privilege.USE_CHAT},
    {'group': 'Workspace', 'label': 'Activity Logs', 'url_name': 'audit:activity', 'icon': 'activity',
     'match': ('audit:activity',), 'privilege': Privilege.VIEW_DASHBOARD},
    {'group': 'Administration', 'label': 'DRM Hub', 'url_name': 'vault:hub', 'icon': 'upload',
     'match': ('vault:hub', 'vault:edit'), 'privilege': Privilege.UPLOAD_PROTECTED_FILES},
    {'group': 'Administration', 'label': 'Access Requests', 'url_name': 'vault:requests', 'icon': 'key',
     'match': ('vault:requests',), 'privilege': Privilege.REVIEW_TEAM_ACCESS_REQUESTS},
    {'group': 'Security', 'label': 'Security Center', 'url_name': 'security:center', 'icon': 'alert',
     'match': ('security:center', 'security:alert'), 'privilege': Privilege.VIEW_SECURITY_CENTER},
    {'group': 'Security', 'label': 'Incidents', 'url_name': 'incidents:list', 'icon': 'case',
     'match': ('incidents:list', 'incidents:create', 'incidents:detail', 'incidents:evidence'),
     'privilege': Privilege.MANAGE_INCIDENTS},
    {'group': 'Security', 'label': 'Forensic Analyzer', 'url_name': 'forensics:analyzer', 'icon': 'search',
     'match': ('forensics:analyzer', 'forensics:report'), 'privilege': Privilege.RUN_FORENSICS},
    {'group': 'Security', 'label': 'Reports', 'url_name': 'reports:summary', 'icon': 'chart',
     'match': ('reports:summary', 'reports:file_access'), 'privilege': Privilege.VIEW_REPORTS},
    {'group': 'Administration', 'label': 'User Management', 'url_name': 'accounts:user_list', 'icon': 'users',
     'match': ('accounts:user_list',), 'privilege': Privilege.MANAGE_USERS},
    {'group': 'Administration', 'label': 'Devices', 'url_name': 'accounts:devices', 'icon': 'monitor',
     'match': ('accounts:devices',), 'privilege': Privilege.MANAGE_DEVICE_POLICY},
    {'group': 'Account', 'label': 'Profile', 'url_name': 'accounts:profile', 'icon': 'user',
     'match': ('accounts:profile', 'accounts:password_change'),
     'privilege': Privilege.MANAGE_OWN_ACCOUNT},
]


def _badges(user, privileges):
    """Small counters next to sidebar items (pending work only)."""
    badges = {}
    if Privilege.REVIEW_TEAM_ACCESS_REQUESTS in privileges:
        from vault.access import requests_visible_to
        from vault.models import AccessRequest
        badges['vault:requests'] = requests_visible_to(user).filter(
            status=AccessRequest.Status.PENDING).count()
    if Privilege.VIEW_SECURITY_CENTER in privileges:
        from security.models import SecurityAlert
        badges['security:center'] = SecurityAlert.objects.filter(status=SecurityAlert.Status.OPEN).count()
    if Privilege.MANAGE_INCIDENTS in privileges:
        from incidents.models import Incident
        badges['incidents:list'] = Incident.objects.filter(assigned_to=user,
                                                           status__in=Incident.ACTIVE_STATUSES).count()
    return badges


def navigation(request):
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}
    from notifications.services import unread_count
    current = getattr(getattr(request, 'resolver_match', None), 'view_name', '')
    privileges = user.privileges
    badges = _badges(user, privileges)
    items = []
    for item in NAV_ITEMS:
        if item['privilege'] and item['privilege'] not in privileges:
            continue
        items.append({
            'group': item['group'],
            'label': item['label'],
            'url': reverse(item['url_name']),
            'icon': item['icon'],
            'active': current in item['match'],
            'badge': badges.get(item['url_name'], 0),
        })
    groups = [{'label': name, 'items': [i for i in items if i['group'] == name]} for name in NAV_GROUPS]
    return {'sv_nav': items, 'sv_nav_groups': [g for g in groups if g['items']],
            'sv_privileges': privileges, 'sv_unread_notifications': unread_count(user)}