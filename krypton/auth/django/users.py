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
    """Django user object"""
    identifier = models.CharField(max_length=40, unique=True)
    email = models.CharField(max_length=40, unique=True)
    USERNAME_FIELD = 'identifier'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []
    is_active = True
    def __init__(self, userName: str) -> None:
        """The title says it all"""
        AbstractBaseUser.set_unusable_password(self)
        standardUser.__init__(self, userName)
    def set_password(raw_password):
        """The title says it all"""
    def check_password(raw_password):
        """The title says it all"""
    def get_session_auth_hash():
        """The title says it all"""
    def save(self, force_insert: bool = ..., force_update: bool = ..., using: Optional[str] = ..., update_fields: Optional[Iterable[str]] = ...) -> None:
        if not self.saved:
            self.saveNewUser()
        return super().save(force_insert, force_update, using, update_fields)


class kryptonUserManager(BaseUserManager):
    def create_user(self, email, password=None, fidoToken=None):
        """Create a new Django User"""


    def create_superuser(self, email, password=None, fidoToken=None):
        """Create a new Django SuperUser"""
