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
    def __init__(self: standardUser, userName: str = None, userID: int = None) -> None:
        """Init a new Django User

        Arguments:
            userID -- User ID
        """
        standardUser.__init__(self, userName, userID)
