from django.urls import path

from . import device_views, management_views, views

app_name = 'accounts'

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('profile/', views.profile_view, name='profile'),
    path('profile/password/', views.SVPasswordChangeView.as_view(), name='password_change'),
    path('profile/sessions/sign-out-others/', views.logout_other_sessions_view,
         name='logout_other_sessions'),
    path('profile/sessions/<int:pk>/end/', views.revoke_session_view, name='revoke_session'),
    path('profile/devices/<uuid:public_id>/remove/', device_views.revoke_own_device_view,
         name='revoke_device'),

    path('password-reset/', views.SVPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/sent/', views.SVPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.SVPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('reset/complete/', views.SVPasswordResetCompleteView.as_view(),
         name='password_reset_complete'),

    # User Management (admin only)
    path('users/', management_views.user_list_view, name='user_list'),
    path('users/<int:pk>/role/', management_views.user_set_role_view, name='user_set_role'),
    path('users/<int:pk>/status/', management_views.user_set_status_view, name='user_set_status'),

    # Device policy and all devices (admin only)
    path('devices/', device_views.device_admin_view, name='devices'),
    path('devices/<uuid:public_id>/remove/', device_views.admin_revoke_device_view,
         name='admin_revoke_device'),
]