from django.urls import path

from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.summary_view, name='summary'),
    path('file-access/', views.file_access_view, name='file_access'),
]