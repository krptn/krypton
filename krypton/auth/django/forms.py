"""
Predefined forms for users to use.
"""
from django.contrib.auth.forms import UserCreationForm
from django import forms
from . import users

class RegisterForm(UserCreationForm):
    """Base form for Django Krypton User Creation"""
    newPWD = forms.PasswordInput(label = "Password")
    userName = forms.CharField(label = "User Name")
    def save(self, commit=True) -> users.djangoUser:
        user = users.djangoUser(None)
        user.saveNewUser(pwd=self.newPWD, name=self.userName)
        return user
## Should we implement Change User? Data is encrypted anyway - how will it be re-encrypted?