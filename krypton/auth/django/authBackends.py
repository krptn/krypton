"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest
from . import users

class kryptonBackend(BaseBackend):
    """
    Authentication Backend for Django.
    """
    def authenticate(self,
            request:HttpRequest,
            username:str,
            creds:dict,
        ):
        """Authenticate User with Credentials

        Arguments:
            request -- Django's HTTPRequest

            username -- Username

            creds -- Dictionary of credentials where password, mfaToken, fidoKey can be mapped.

        Returns:
            User Model or None is authentication fails
        """
        try:
            user = users.djangoUser(username)
            token = user.login(password=creds["password"], mfaToken=creds["mfaToken"], fido=creds["fido"])
            UId = user.id
        except:
            return None
        request.session["_KryptonSessionToken"] = token
        request.session["_KryptonUserID"] = UId
        return user

    def get_user(self, user_id: int):
        """Gets a user from an id"""
        user = users.djangoUser(user_id)
        if user.saved:
            return user
        return None
