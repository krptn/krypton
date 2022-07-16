from functools import wraps
from ... import configs

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
def loginRequired(func):
    @wraps(func)
    def inner(request:HttpRequest, *args, **kwargs):
        if not request.loggedin:
            if configs.defaultErrorPage != "":
                return render(request, configs.defaultErrorPage)
            else:
                return HttpResponse(403)
        return func(request, *args, **kwargs)
    return inner