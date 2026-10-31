from django.urls import path

from . import views

app_name = 'teams'

urlpatterns = [
    path('', views.team_list_view, name='list'),
    path('new/', views.team_create_view, name='create'),
    path('<int:pk>/', views.team_detail_view, name='detail'),
    path('<int:pk>/edit/', views.team_edit_view, name='edit'),
    path('<int:pk>/members/add/', views.team_add_members_view, name='add_members'),
    path('<int:pk>/members/<int:user_pk>/remove/', views.team_remove_member_view,
         name='remove_member'),
]