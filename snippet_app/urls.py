from django.conf.urls import url

from .views import (RegisterView, LoginView, AddSnippet, ShareSnippet)
from rest_framework.authtoken import views

urlpatterns = [
    url('register/', RegisterView.as_view(), name='register'),
    url('login/', LoginView.as_view(), name='login'),
    url('text/', AddSnippet.as_view(), name='add_snippet'),
    url('share/', ShareSnippet.as_view(), name='share'),
    url(r'get_snippet', AddSnippet.as_view(), name='get_snippet'),
]
