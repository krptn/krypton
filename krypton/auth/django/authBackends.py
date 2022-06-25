"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from .. import login
from . import users

class kryptonBackend(BaseBackend):
    """
    Authentication Backend for Django.
    """
    def authenticate(self, request, username=None, password=None, mfaToken=None, fidoKey=None):
        """Authenticates a user with supplied credentials"""
        try:
            user = login.authUser(username, password, mfaToken, fidoKey)
        except login.UserDoesNotExist:
            user = users.djangoUser(userName=username)
            user.saveNewUser()
        return user

    def get_user(self, user_id: int):
        """Gets a user from an id"""
