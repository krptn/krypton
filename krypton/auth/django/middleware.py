"""
Django middleware to add user object as needed to the request.
"""
from .users import djangoUser
from ..users import UserError
from django.http import HttpRequest


def kryptonLoginMiddleware(get_response):
    """
    Django middleware to add user object as needed to the request.
    """
    # One-time configuration and initialization.
    def skipAuth(request:HttpRequest):
        """
        Return without login
        """
        response = get_response(request)
        return response
    def KrLoginMiddleWare(request:HttpRequest):
        """
        Middleware
        """
        auth = False
        try: 
            token = request.session["_KryptonSessionToken"]
            Uid = request.session["_KryptonUserID"]
        except KeyError:
            return skipAuth(request)
        user = djangoUser(Uid)
        try: user.restoreSession(token)
        except UserError:
            return skipAuth(request)
        request.user = user
        response = get_response(request)
        # Code to be executed for each request/response after
        # the view is called.
        return response
    return KrLoginMiddleWare