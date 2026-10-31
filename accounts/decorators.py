from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

from audit.models import AuditLog
from audit.services import log_event


def privilege_required(*codes):
    """Server-side enforcement: the user must be signed in AND hold every
    listed privilege. Otherwise the attempt is audited and a 403 is returned,
    no matter what the page's buttons showed."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            missing = [code for code in codes if not request.user.has_privilege(code)]
            if missing:
                log_event(AuditLog.Action.ACCESS_DENIED, request=request,
                          target=request.path, result=AuditLog.Result.DENIED,
                          details={'missing_privileges': missing, 'role': request.user.role})
                raise PermissionDenied
            return view_func(request, *args, **kwargs)
        return login_required(_wrapped)
    return decorator