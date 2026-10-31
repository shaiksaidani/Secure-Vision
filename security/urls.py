from django.urls import path

from . import views

app_name = 'security'

urlpatterns = [
    path('', views.center_view, name='center'),
    path('alerts/<uuid:public_id>/', views.alert_view, name='alert'),
    path('alerts/<uuid:public_id>/update/', views.alert_update_view, name='alert_update'),
]