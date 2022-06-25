"""
Functions to manage user logi for django.
"""

class UserDoesNotExist(Exception):
    """Exception to be raised on error when a non-existend user is authenticated"""
    def __init__(self, *args: object) -> None:
        self.message = args[0]
        super().__init__()
    def __str__(self) -> str:
        return self.message

def authUser(userId, *creds):
    """Authenticate a user and return user object"""
    pass

def newUserFromForm(self, commit=True, *args):
    """Authenticate a user and return user object from Form Data"""
    pass