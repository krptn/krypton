"""
Django middleware to add user object as needed to the request.
"""

from django.http import HttpRequest
from .users import djangoUser
from ..users.userModel import UserError


def kryptonLoginMiddleware(get_response):
    """Django middleware to add user object as needed to the request.


    Arguments:
        get_response -- Function to get HttpResponse

    Returns:
        Response
    """
    def skipAuth(request:HttpRequest):
        """Skip Login

        Arguments:
            request -- HttpRequest

        Returns:
            HttpResponse
        """
        return get_response(request)
    def KrLoginMiddleWare(request:HttpRequest):
        """Middleware

        Arguments:
            request -- HttpRequest

        Returns:
            HttpResponse
        """
        try:
            user = djangoUser(userID = request.COOKIES["_KryptonUserID"])
            user.restoreSession(request.COOKIES["_KryptonSessionToken"])
        except UserError: return skipAuth(request)
        except KeyError: return skipAuth(request)
        request.user = user
        return get_response(request)
    return KrLoginMiddleWare
