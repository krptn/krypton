# User Authentication

**Note:** to use Authentication in a supported web framework please see [integrations](README-INTEGRATIONS.md).
**Note:** username's are not encrypted - everything else is.

Here is an example usage of creating a new user:

```python
from krypton.auth import users

model = users.standardUser(None)
model.saveNewUser("Test_UserName", "Test_Password") # MFA support will be added soon
```

To retreive the user and set user data as key-value pairs:

```python
model = users.standardUser(userName="Test_UserName")
sessionKey = model.login(pwd="Test_Password") # See below what sessionKey is
model.setData("test", "example") # test is the key and example is the value
data = model.getData("test") # Gives b"example"
model.deleteData("test")
```

You can also use model.encryptWithUserKey and model.decryptWithUserKey if you want to use your own database: see [cross-user encryption](#cross-user-encryption). Also, cross-user encryption is has other uses so read it anyway!

***Warning: in setData only the stored values are encrypted. Keys are plaintext!! Avoid storing sensitive data in keys!***

Session keys can be used to restore a session after the user object has been destroyed.
For example, in a webserver, it would be passed in every request to fetch the user.

To restore a session:

```python
model = users.standardUser(userName="Test_UserName")
model.restoreSession(sessionKey)
```

To set session expiry please see [Configuration](README-CONFIGS.md)

## Cross-User Encryption

Using this method, you can grant access to some of the user's account's data to another user.

```python
from krypton.auth import users

model = users.standardUser(None)
model.saveNewUser("Test_UserName", "Test_Password")

model2 = users.standardUser(None)
model2.saveNewUser("Test_UserName2", "Test_Password")

r = model.encryptWithUserKey("data")
model.decryptWithUserKey(r) # Returns b"data"

## Here is the tricky part:

r = model.encryptWithUserKey("data", ["Test_UserName2"]) # Allow Test_UserName to decrypt the data
model2.decryptWithUserKey(r[0][1], r[0][2], "Test_UserName") # Returns b"data"
```

### Let us explain this

encryptWithUserKey needs to parameters: `data`, `otherUsers` (optional). `data` is the plaintext to encrypt and `otherUsers` is a list of usernames of users who can also decrypt the data.

encryptWithUserKey returns a list of tuples in the following format: `(username, data, salt)`. `username` is the name of the user to who we need to provide `data` and `salt`.

When decrypting, call decryptUserKey, on the user object corresponding to `username`, passing `data` as the first argument and `salt` as the second argument. It will return the plaintext.

Therefore, by using this method, you can grant access to some of the user's account's data to another user, simply by allowing that user to decrypt the user data.
