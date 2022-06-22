from django.contrib.auth.forms import UserCreationForm
from django import forms
from .. import login, users

class RegisterForm(UserCreationForm):
    email = forms.EmailField(label = "Email")
    fullname = forms.CharField(label = "First name")
    def save(self, commit=True) -> users.djangoUser:
        user = login.newUserFromForm(self, commit=commit)
        return user