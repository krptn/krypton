from .. import DBschemas
from sqlalchemy import select, func
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
