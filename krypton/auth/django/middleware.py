from .users import djangoUser
from ..users import UserError
from django.http import HttpRequest


def kryptonLoginMiddleware(get_response):
    # One-time configuration and initialization.
    def skipAuth(request:HttpRequest):
            response = get_response(request)
            return response
    def KrLoginMiddleWare(request:HttpRequest):
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