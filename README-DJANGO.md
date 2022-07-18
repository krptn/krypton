# Django Integration

Please configure your Django project to use the following Auth Backend:

```python
krypton.auth.django.authBackends.kryptonBackend
```

Also note, that when you pass a request to authenticate in the backend, it will set auth cookies inside the request's session. Therefore, it is not necessary to use django's `login` function.

Please point the User Manager to be krypton.auth.django.users.kryptonUserManager or to a subclass of it

Please make sure that in your user registration form your saved method is configured like this:

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

Important please add krypton middleware to END OF THE LIST:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'krypton.auth.django.middleware.kryptonLoginMiddleware' ## <-- Like here
]
```

In order to ensure a user is authenticated before visitng your site, you can add the loginRequired deocrator from krypton.auth.django.simple.loginRequired.