from django.urls import path

from . import views

app_name = 'chat'

urlpatterns = [
    path('', views.chat_home_view, name='home'),
    path('c/<uuid:public_id>/', views.conversation_view, name='conversation'),
    path('c/<uuid:public_id>/send/', views.send_message_view, name='send'),
    path('c/<uuid:public_id>/updates/', views.updates_view, name='updates'),
    path('with/<int:user_pk>/', views.start_direct_view, name='start'),
    path('team/<int:team_pk>/', views.team_chat_view, name='team'),
    path('message/<int:message_pk>/delete/', views.delete_message_view, name='delete'),
]