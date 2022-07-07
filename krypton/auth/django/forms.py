"""
Predifined forms for users to use.
"""
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from . import users

class RegisterForm(UserCreationForm):
    newPWD = forms.PasswordInput(label = "Password")
    userName = forms.CharField(label = "User Name")
    def save(self, commit=True) -> users.djangoUser:
        user = users.djangoUser(None)
        user.saveNewUser(pwd=self.newPWD, name=self.userName)
        return user
## Should we implement the below? Data is encrypted anyway - how will it be re-encrpted?
"""class ChangeForm(UserChangeForm):    
    newPWD = forms.PasswordInput(label = "Password")
    userName = forms.CharField(label = "User Name")
    def save(self, commit=True) -> users.djangoUser:
        user = users.djangoUser(self.userName)
        user.resetPWD()
        return user"""