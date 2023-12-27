from django.http import HttpRequest
from . import users

class KrHttpRequest(HttpRequest):
    user: users.djangoUser
