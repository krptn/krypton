"""Helpers for Django Integration"""

from functools import wraps
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from ... import configs

def loginRequired(func):
    """User has to be logged in to continue"""
    @wraps(func)
    def inner(request:HttpRequest, *args, **kwargs):
        """User has to be logged in to continue"""
        if not request.loggedin:
            if configs.defaultErrorPage != "":
                return render(request, configs.defaultErrorPage)
            return HttpResponse(403)
        return func(request, *args, **kwargs)
    return inner
