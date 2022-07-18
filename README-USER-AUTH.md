# User Authenication

Here is an example usage of creating a new user:

```python
from krypton.auth import users

model = users.standardUser(None)
user = user.saveNewUser("Test_UserName", "Test_Password") # MFA support will be added soon
```

To retreive the user:

```python
model = users.standardUser(userName="Test_UserName")
sessionKey = model.login(pwd="Test_Password") # See below what sessionKey is
model.setData("test", "example") # test is the key and example is the value
data = model.getData("test") # Gives b"example"
model.deleteData("test")
```

***Warning: in setData only the stored values are encrypted. Keys are plaintext!! Avoid storing sensitive data in keys!***

Session keys can be used to restore a session after the user object has been destroyed.
For example, in a webserver, it would be passed in every request to fetch the user.

To restore a session:

```python
model = users.standardUser(userName="Test_UserName")
model.restoreSession(sessionKey)
```

To set session expiry please see [Configuration](README-CONFIGS.md)