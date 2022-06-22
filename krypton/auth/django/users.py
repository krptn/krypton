from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from ..users import standardUser

class djangoUser(standardUser, AbstractBaseUser):
    pass

class kryptonUserManager(BaseUserManager):
    def create_user(self, email, date_of_birth, password=None):
        pass

    def create_superuser(self, email, date_of_birth, password=None):
        pass