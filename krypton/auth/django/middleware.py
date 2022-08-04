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
    # One-time configuration and initialization.
    def skipAuth(request:HttpRequest):
        """Skip Login

        Arguments:
            request -- HttpRequest

        Returns:
            HttpResponse
        """
        response = get_response(request)
        return response
    def KrLoginMiddleWare(request:HttpRequest):
        """Middleware

        Arguments:
            request -- HttpRequest

        Returns:
            HttpResponse
        """
        try:
            token = request.session["_KryptonSessionToken"]
            Uid = request.session["_KryptonUserID"]
        except KeyError:
            return skipAuth(request)
        user = djangoUser(userID = Uid)
        try:
            user.restoreSession(token)
        except UserError:
            return skipAuth(request)
        request.user = user
        response = get_response(request)
        # Code to be executed for each request/response after
        # the view is called.
        return response
    return KrLoginMiddleWare
