from django.urls import path

from . import views

app_name = 'forensics'

urlpatterns = [
    path('', views.analyzer_view, name='analyzer'),
    path('<uuid:public_id>/', views.report_view, name='report'),
]