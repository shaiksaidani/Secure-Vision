from django.urls import path

from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.list_view, name='list'),
    path('<int:pk>/open/', views.open_view, name='open'),
    path('read-all/', views.mark_all_read_view, name='read_all'),
]