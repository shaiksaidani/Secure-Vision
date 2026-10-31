from django.urls import path

from . import views

app_name = 'attendance'

urlpatterns = [
    path('', views.my_attendance_view, name='mine'),
    path('check-in/', views.check_in_view, name='check_in'),
    path('check-out/', views.check_out_view, name='check_out'),
    path('team/', views.manage_view, name='manage'),
    path('team/mark/', views.mark_view, name='mark'),
    path('reports/', views.report_view, name='report'),
]