"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import login
from django.http import HttpRequest
from sqlalchemy import select
from ... import DBschemas, base, Globalsalt
from ..users import ITER, LEN
from . import users

class kryptonBackend(BaseBackend):
    """
    Authentication Backend for Django.
    """
    def authenticate(self, request:HttpRequest, username=None, password=None, mfaToken=None, fidoKey=None):
        """Authenticates a user with supplied credentials"""
        stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == base.PBKDF2(username, Globalsalt, ITER, LEN)).limit(1)
        try:
            Uid = self.c.scalar(stmt)[0]
        except:
            return None
        user = users.djangoUser(Uid)
        try: token = user.login(pwd=password, otp=mfaToken, fido=fidoKey)
        except: return None
        request.session["_KryptonSessionToken"] = token
        request.session["_KryptonUserID"] = Uid
        return user

    def get_user(self, user_id: int):
        """Gets a user from an id"""
        user = users.djangoUser(user_id)
        if user.saved:
            return user
        return None