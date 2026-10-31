from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege

from .models import Notification


def _safe_internal(url):
    """Only follow links back into SecureVision."""
    return bool(url) and url.startswith('/') and not url.startswith('//') and '\\' not in url


@privilege_required(Privilege.VIEW_DASHBOARD)
def list_view(request):
    items = Notification.objects.filter(user=request.user)
    page = Paginator(items, 30).get_page(request.GET.get('page'))
    return render(request, 'notifications/list.html', {
        'page': page, 'unread': items.filter(read_at__isnull=True).count(),
    })


@privilege_required(Privilege.VIEW_DASHBOARD)
def open_view(request, pk):
    item = get_object_or_404(Notification, pk=pk, user=request.user)
    if item.read_at is None:
        Notification.objects.filter(pk=item.pk).update(read_at=timezone.now())
    return redirect(item.url if _safe_internal(item.url) else 'notifications:list')


@privilege_required(Privilege.VIEW_DASHBOARD)
@require_POST
def mark_all_read_view(request):
    Notification.objects.filter(user=request.user, read_at__isnull=True).update(read_at=timezone.now())
    return redirect('notifications:list')