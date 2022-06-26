"""
Authentication Backends for Django.
"""
from django.contrib.auth.backends import BaseBackend
from sqlalchemy import select
from ... import DBschemas
from . import users

class kryptonBackend(BaseBackend):
    """
    Authentication Backend for Django.
    """
    def authenticate(self, request, username=None, password=None, mfaToken=None, fidoKey=None):
        """Authenticates a user with supplied credentials"""
        stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == username).limit(1)
        try:
            self.c.scalar(stmt)[0]
            user = users.djangoUser(username)
        except:
            user = users.djangoUser(username)
            user.saveNewUser()
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

