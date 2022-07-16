"""
Django user objects and user managers.
"""
from typing import Iterable, Optional
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from ..users import standardUser

class djangoUser(standardUser, AbstractBaseUser):
    def __init__(self, userID: str) -> None:
        standardUser.__init__(self, userID)
        self.is_authenticated = self.loggedin

class kryptonUserManager(BaseUserManager):
    def create_user(self, email, password=None, fidoToken=None):
        """Create a new Django User"""
        user = djangoUser(email)
        user.saveNewUser(pwd=password, fido=fidoToken)

    def create_superuser(self, email, password=None, fidoToken=None):
        """Create a new Django SuperUser"""
