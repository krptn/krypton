"""
Django user objects and user managers.
"""

from ..users.userModel import standardUser, user

from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)

class djangoUser(standardUser):
    """Django wrapper for Krypton User
    """
    @property
    def is_authenticated(self) -> bool:
        return self.loggedin
    def __init__(self: standardUser, userName: str = None, userID: int = None) -> None:
        """Init a new Django User

        Arguments:
            userID -- User ID
        """
        standardUser.__init__(self, userName, userID)
        self.is_authenticated = self.loggedin

class kryptonUserManager(BaseUserManager):
    """Krypton User Manager for Django
    """
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
