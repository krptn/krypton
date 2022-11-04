"""
Django user objects and user managers.
"""

from ..users.userModel import standardUser

class djangoUser(standardUser):
    """Django wrapper for Krypton User
    """
    @property
    def is_authenticated(self) -> bool:
        """Returns the user's authentication state

        Returns:
            True is authenticated, False otherwise
        """
        return self.loggedin
