"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest
from sqlalchemy import select
from ... import DBschemas, base, Globalsalt, configs
from ..users import ITER, LEN
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
        """Authenicate User with Credentials

        Arguments:
            request -- Django's HTTPRequest

            username -- Username

            creds -- Dictionary of credentials where password, mfaToken, fidoKey can be mapped.

        Returns:
            User Model or None is authentication fails
        """
        stmt = select(DBschemas.UserTable.id).where(
            DBschemas.UserTable.name == base.PBKDF2(username, Globalsalt, ITER, LEN)
            ).limit(1)
        UId = configs.SQLDefaultUserDBpath.scalar(stmt)
        if UId is None:
            return None
        user = users.djangoUser(UId)
        try:
            token = user.login(pwd=creds["password"], mfaToken=creds["mfaToken"], fido=creds["fidoKey"])
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
