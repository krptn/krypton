"""
Django user objects and user managers.
"""

from ..users.userModel import standardUser

class djangoUser(standardUser):
    """Django wrapper for Krypton User
    """
    @property
    def is_authenticated(self) -> bool:
        return self.loggedin
