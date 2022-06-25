"""
Django user objects and user managers.
"""
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from ..users import standardUser

class djangoUser(standardUser, AbstractBaseUser):
    """Django user object"""


class kryptonUserManager(BaseUserManager):
    def create_user(self, email, password=None, fidoToken=None):
        """Create a new Django User"""


    def create_superuser(self, email, password=None, fidoToken=None):
        """Create a new Django SuperUser"""
