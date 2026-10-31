from django.urls import path

from . import request_views, views

app_name = 'vault'

urlpatterns = [
    path('', views.stored_data_view, name='stored_data'),
    path('hub/', views.drm_hub_view, name='hub'),
    path('<uuid:public_id>/', views.file_viewer_view, name='viewer'),
    path('<uuid:public_id>/content/', views.file_content_view, name='content'),
    path('<uuid:public_id>/download/', views.file_download_view, name='download'),
    path('<uuid:public_id>/access/', views.file_edit_view, name='edit'),
    path('<uuid:public_id>/request-access/', request_views.request_access_view, name='request_access'),
    path('requests/', request_views.requests_view, name='requests'),
    path('requests/<uuid:public_id>/decide/', request_views.decide_view, name='decide'),
]