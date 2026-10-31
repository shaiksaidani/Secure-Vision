"""
Role-based privileges for SecureVision.

This is the ONE place that defines what each role may do. Views enforce it on
the server with @privilege_required(...). Templates only use it to decide what
to show; hiding a button is never the security control.
"""


class Privilege:
    # Everyone
    VIEW_DASHBOARD = 'view_dashboard'
    MANAGE_OWN_ACCOUNT = 'manage_own_account'
    VIEW_AUTHORIZED_FILES = 'view_authorized_files'
    REQUEST_FILE_ACCESS = 'request_file_access'
    USE_CHAT = 'use_chat'
    CHECK_IN_OUT = 'check_in_out'
    VIEW_OWN_TEAM = 'view_own_team'
    # Team leaders
    POST_TEAM_ANNOUNCEMENTS = 'post_team_announcements'
    VIEW_TEAM_ATTENDANCE = 'view_team_attendance'
    REVIEW_TEAM_ACCESS_REQUESTS = 'review_team_access_requests'
    # Admins
    MANAGE_USERS = 'manage_users'
    MANAGE_TEAMS = 'manage_teams'
    UPLOAD_PROTECTED_FILES = 'upload_protected_files'
    MANAGE_FILE_PERMISSIONS = 'manage_file_permissions'
    REVIEW_ALL_ACCESS_REQUESTS = 'review_all_access_requests'
    MANAGE_ATTENDANCE = 'manage_attendance'
    MANAGE_DEVICE_POLICY = 'manage_device_policy'
    VIEW_AUDIT_LOGS = 'view_audit_logs'
    VIEW_SECURITY_CENTER = 'view_security_center'
    RUN_FORENSICS = 'run_forensics'
    MANAGE_INCIDENTS = 'manage_incidents'
    VIEW_REPORTS = 'view_reports'


# (code, label, phase in which the module that uses it is delivered)
PRIVILEGE_CATALOG = [
    (Privilege.VIEW_DASHBOARD, 'View dashboard', 1),
    (Privilege.MANAGE_OWN_ACCOUNT, 'Manage own profile, password and sessions', 1),
    (Privilege.VIEW_OWN_TEAM, 'View own team', 2),
    (Privilege.VIEW_AUTHORIZED_FILES, 'Open files they are authorized for', 3),
    (Privilege.REQUEST_FILE_ACCESS, 'Request access to restricted files', 7),
    (Privilege.USE_CHAT, 'Use confidential and team chat', 4),
    (Privilege.CHECK_IN_OUT, 'Check in and out (attendance)', 5),
    (Privilege.POST_TEAM_ANNOUNCEMENTS, 'Post team announcements', 4),
    (Privilege.VIEW_TEAM_ATTENDANCE, "View their team's attendance", 5),
    (Privilege.REVIEW_TEAM_ACCESS_REQUESTS, "Review their team's access requests", 7),
    (Privilege.MANAGE_USERS, 'Manage users and roles', 1),
    (Privilege.MANAGE_TEAMS, 'Create and manage teams', 2),
    (Privilege.UPLOAD_PROTECTED_FILES, 'Upload protected files', 3),
    (Privilege.MANAGE_FILE_PERMISSIONS, 'Manage file permissions and expiry', 3),
    (Privilege.REVIEW_ALL_ACCESS_REQUESTS, 'Review all access requests', 7),
    (Privilege.MANAGE_ATTENDANCE, 'Manage attendance reports', 5),
    (Privilege.MANAGE_DEVICE_POLICY, 'Set device policy', 5),
    (Privilege.VIEW_AUDIT_LOGS, 'View audit logs', 7),
    (Privilege.VIEW_SECURITY_CENTER, 'View security alerts', 7),
    (Privilege.RUN_FORENSICS, 'Run forensic analysis', 6),
    (Privilege.MANAGE_INCIDENTS, 'Manage incidents and evidence', 8),
    (Privilege.VIEW_REPORTS, 'View and export reports', 8),
]

CURRENT_PHASE = 8

EMPLOYEE_PRIVILEGES = frozenset([
    Privilege.VIEW_DASHBOARD,
    Privilege.MANAGE_OWN_ACCOUNT,
    Privilege.VIEW_AUTHORIZED_FILES,
    Privilege.REQUEST_FILE_ACCESS,
    Privilege.USE_CHAT,
    Privilege.CHECK_IN_OUT,
    Privilege.VIEW_OWN_TEAM,
])

TEAM_LEADER_PRIVILEGES = EMPLOYEE_PRIVILEGES | frozenset([
    Privilege.POST_TEAM_ANNOUNCEMENTS,
    Privilege.VIEW_TEAM_ATTENDANCE,
    Privilege.REVIEW_TEAM_ACCESS_REQUESTS,
])

ADMIN_PRIVILEGES = frozenset(code for code, _label, _phase in PRIVILEGE_CATALOG)

# Keys match User.Role values.
ROLE_PRIVILEGES = {
    'EMPLOYEE': EMPLOYEE_PRIVILEGES,
    'TEAM_LEADER': TEAM_LEADER_PRIVILEGES,
    'ADMIN': ADMIN_PRIVILEGES,
}

ROLE_DESCRIPTIONS = {
    'EMPLOYEE': 'Authorized files, chat, attendance and your own team.',
    'TEAM_LEADER': 'Everything an employee has, plus team announcements, '
                   'team attendance and team access requests.',
    'ADMIN': 'Full control: users, roles, teams, protected files, attendance, '
             'devices, security and audit.',
}


def privileges_for_role(role):
    return ROLE_PRIVILEGES.get(role, frozenset())


def privilege_rows(privileges):
    """Rows for display: label + whether its module is already available."""
    return [
        {'label': label, 'live': phase <= CURRENT_PHASE, 'phase': phase}
        for code, label, phase in PRIVILEGE_CATALOG if code in privileges
    ]