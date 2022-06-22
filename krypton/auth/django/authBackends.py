from django.contrib.auth.backends import BaseBackend
from .. import login
from . import users

class kryptonBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, mfaToken=None, fidoKey=None):
        try: 
            user = login.authUser(username, password, mfaToken, fidoKey)
        except login.UserDoesNotExist:
            user = users.djangoUser(userName=username)
            user.saveNewUser()
        return user
    
    def get_user(self, user_id: int):
        pass