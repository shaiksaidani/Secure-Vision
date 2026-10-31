from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('', include('core.urls')),
    path('accounts/', include('accounts.urls')),
    path('teams/', include('teams.urls')),
    path('files/', include('vault.urls')),
    path('chat/', include('chat.urls')),
    path('attendance/', include('attendance.urls')),
    path('forensics/', include('forensics.urls')),
    path('activity/', include('audit.urls')),
    path('security/', include('security.urls')),
    path('notifications/', include('notifications.urls')),
    path('incidents/', include('incidents.urls')),
    path('reports/', include('reports.urls')),
    # Django's built-in admin is kept for superuser database inspection only.
    path('sv-admin/', admin.site.urls),
]