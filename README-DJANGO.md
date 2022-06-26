Please configure your Django project to use the following Auth Backend:
```python
krypton.auth.django.authBackends.kryptonBackend
```

Also, replace your user model to krypton.auth.django.users.djangoUser
For custom user models please define you model to inherit krypton.auth.django.users.djangoUser.

Please point the User Manager to be krypton.auth.django.users.kryptonUserManager or to a subclass of it

Please make sure that in your user registration form your saved method is coded like this:
```python
from krypton.auth.django import login
class RegisterForm(UserCreationForm):
    ...
    save = login.newUserFromForm
```

Alternatively you can use the predefined form in krypton.auth.django.forms

```python
from krypton.auth.django import forms
form = forms.RegisterForm
```
