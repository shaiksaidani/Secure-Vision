from django.urls import path

from . import views

app_name = 'incidents'

urlpatterns = [
    path('', views.incident_list_view, name='list'),
    path('new/', views.incident_create_view, name='create'),
    path('<uuid:public_id>/', views.incident_detail_view, name='detail'),
    path('<uuid:public_id>/update/', views.incident_update_view, name='update'),
    path('<uuid:public_id>/evidence/upload/', views.evidence_upload_view, name='evidence_upload'),
    path('<uuid:public_id>/evidence/snapshot/', views.evidence_snapshot_view, name='evidence_snapshot'),
    path('<uuid:public_id>/link-analysis/', views.link_analysis_view, name='link_analysis'),
    path('<uuid:public_id>/report/', views.incident_report_view, name='report'),
    path('evidence/<uuid:public_id>/', views.evidence_detail_view, name='evidence'),
    path('evidence/<uuid:public_id>/verify/', views.evidence_verify_view, name='evidence_verify'),
    path('evidence/<uuid:public_id>/download/', views.evidence_download_view, name='evidence_download'),
]