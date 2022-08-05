# User Authentication

**Note:** to use Authentication in a supported web framework please see [integrations](README-INTEGRATIONS.md).

**Please note:** this not protect you against brute force attacks - make sure to enable rate limiting on your host.

**Note:** usernames are not encrypted.

**Note:** user classes are not thread-safe. Please create a new one to use in each thread!

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

**Note:** do make sure that the key in setData does not start with `_` - those are reserved for Krypton internals.

You can also use model.encryptWithUserKey and model.decryptWithUserKey if you want other users to decrypt it [cross-user data sharing](##data-sharing--encryption).

***Warning: in setData only the stored values are encrypted. Keys are plaintext!! Avoid storing sensitive data in keys!***

Session keys can be used to restore a session after the user object has been destroyed.
For example, in a webserver, it would be passed in every request to fetch the user.

To restore a session:

```python
model = users.standardUser(userName="Test_UserName")
model.restoreSession(sessionKey)
```

To set session expiry please see [Configuration](README-CONFIGS.md)

## Sign out of all sessions

```python
model.revokeSessions()
```

## MFA

### TOTP

To enable:

```python
secret, qr = model.enableMFA() 
# Secret is a shared secret and qr is a string, that when converted to QR code can be scanned by authenticator apps. 
# If QR Codes are not supported by the app, you can tell the user enter secret instead. 
# You MUST discard these once the user enabled MFA.
```

When logging in:

```python
model.login(pwd="pwd", mfaToken="123456")
```

### FIDO Passwordless

See [FIDO Docs](README-FIDO.md).

## Data Sharing & Encryption

Using these methods, you can grant access to some of the user's account's data to another user.

While using these methods, all data remains encrypted using the user's credentials, no data is ever plaintext in a database. We use `Elliptic-curve Diffie–Hellman` to share a common encryption key between the users and encrypt the data with it. Each user has their own key, with the private key encrypted with the user's credentials.

### Sharing

```python
from krypton.auth import users

model = users.standardUser(None)
model.saveNewUser("Test_UserName", "Test_Password") # Note: if a user with the same username exists an ValueError will be raised.

model2 = users.standardUser(None)
model2.saveNewUser("Test_UserName2", "Test_Password")

# Save value "data" with key "test" and allow access to user "Test_UserName"
user2.shareSet("test", "data", ["Test_UserName"])
value = model.shareGet("test") # returns b"data"
```

**Note:** do make sure that the key in shareSet does not start with `_` - those are reserved for Krypton internals.

As you can see above, `shareSet` requires you to pass a unique name for the data (`"test"` in this case), the data (`"data"` in this case), and a list of usernames who can access it (`["Test_UserName"]` above).

### Encryption

When possible we it is prefered to use `shareSet` and `shareGet` but when required you can directly use only Krypton's encryption capabilities. E.g: if you want to use another database to store this data.

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

encryptWithUserKey needs to parameters: `data`, `otherUsers` (optional). `data` is the plaintext to encrypt and `otherUsers` is a list of usernames of users who can also decrypt the data.

encryptWithUserKey returns a list of tuples in the following format: `(username, data, salt)`. `username` is the name of the user to who we need to provide `data` and `salt`.

When decrypting, call decryptUserKey, on the user object corresponding to `username`, passing `data` as the first argument and `salt` as the second argument. It will return the plaintext.

Therefore, by using this method, you can grant access to some of the user's account's data to another user, simply by allowing that user to decrypt the user data.

## Password Reset

To enable password reset you need to provide an answer to a security question. The question istelf is irrelevant to Krypton therefore it is enough to provide the answer.

```python
keys = model.enablePWDReset() # keys is a list of OTPs that can be used to unlock the user account
model.logout() # This is not needed but you can reset the password of a locked out user.
model.resetPWD(keys[0], "newPWD") # Note: you cannot use keys[0] again - use keys[1] next.
model.logout() # Note: when you call resetPWD the model will automatically login, you may want to logout
```

If the OTPs get compromised you can revoke them and generate new ones:

```python
model.disablePWDReset() # Revoke
keys = model.enablePWDReset() # Generate. This also revokes all codes but already did so previously.
```
