from django.urls import path
from . import views 

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('registration/', views.registration, name='registration'),
    path('healthInsights/', views.healthInsights, name='healthInsights'),
    path('wellness/', views.wellness_view, name='wellness'),
]