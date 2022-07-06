"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import login
from django.http import HttpRequest
from sqlalchemy import select
from ... import DBschemas
from . import users

class kryptonBackend(BaseBackend):
    """
    Authentication Backend for Django.
    """
    def authenticate(self, request:HttpRequest, username=None, password=None, mfaToken=None, fidoKey=None):
        """Authenticates a user with supplied credentials"""
        stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == username).limit(1)
        try:
            self.c.scalar(stmt)[0]
        except:
            return None
        user = users.djangoUser(username)
        try: token = user.login(pwd=password, otp=mfaToken, fido=fidoKey)
        except: return None
        request.session["KryptonSessionToken"] = token
        login(request, user)
        return user

    def get_user(self, user_id: int):
        """Gets a user from an id"""
        stmt = select(DBschemas.UserTable.name).where(DBschemas.UserTable.id == user_id).limit(1)
        try: 
            name = self.c.scalar(stmt)[0]
            user = users.djangoUser(name)
        except:
            return None
        return user

