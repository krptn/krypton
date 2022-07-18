"""
Django user objects and user managers.
"""

from ..users import standardUser
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)

class djangoUser(standardUser, AbstractBaseUser):
    """Django wrapper for Krypton USer
    """
    def __init__(self, userID: str) -> None:
        """Init a new Django User

        Arguments:
            userID -- User ID
        """
        standardUser.__init__(self, userID)
        self.is_authenticated = self.loggedin

class kryptonUserManager(BaseUserManager):
    def create_user(self, email, password=None, fidoToken=None):
        """Create a new Django User

        Arguments:
            email -- Email of user

        Keyword Arguments:
            password -- Password (default: {None})

            fidoToken -- Fido Token (default: {None})
        """
        user = djangoUser(email)
        user.saveNewUser(pwd=password, fido=fidoToken)

    def create_superuser(self, email, password=None, fidoToken=None):
        """Create a new Django SuperUser"""
