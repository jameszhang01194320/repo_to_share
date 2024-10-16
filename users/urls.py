from django.urls import path
from .views import RegisterView, LoginView, PasswordResetView

urlpatterns = [
    path('signup/', RegisterView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('reset-password/<int:id>/', PasswordResetView.as_view(), name='reset_password'),
]
