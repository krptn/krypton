"""
Django middleware to add user object as needed to the request.
"""

from typing import Callable
from django.http import HttpRequest, HttpResponse
from .users import djangoUser
from ..users.bases import UserError
from . types import KrHttpRequest

def kryptonLoginMiddleware(get_response: Callable[[KrHttpRequest], HttpResponse]):
    """Django middleware to add user object as needed to the request.


    Arguments:
        get_response -- Function to get HttpResponse

    Returns:
        Response
    """

    def KrLoginMiddleWare(request: HttpRequest) -> HttpResponse:
        """Middleware

        Arguments:
            request -- HttpRequest

        Returns:
            HttpResponse
        """
        try:
            user = djangoUser(userID=int(request.COOKIES["_KryptonUserID"]))
            user.restoreSession(request.COOKIES["_KryptonSessionToken"])
        except UserError:
            return get_response(request)
        except KeyError:
            return get_response(request)
        request.user = user
        return get_response(request)

    return KrLoginMiddleWare
