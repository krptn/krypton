# Configuration

**Note:** a change in settings will not result in decryption and re-encryption of data to apply the changes. Instead, they are applied when new data is encrypted, or old data modified - thereby slowly phasing out the old configuration.

Simple, pythonic configuration:

```python
import krypton

krypton.configs.defaultAlgorithm = "AES256GCM" # Sets which symmetric cipher to use (currently only AES256GCM is supported)

krypton.configs.defaultIterations = 600000 # Number of iterations for PBKDF2

krypton.configs.defaultCryptoperiod = 2 # Approx. number of years for the cryptoperiod of a key

krypton.configs.defaultSessionPeriod = 15 # Number of minutes before a user Session is destroyed.

krypton.configs.APP_NAME = # the name of the app to generate MFA codes for
```

## Databases

For the following settings please see [Databases](README-DATABASES.md)

```python
krypton.configs.SQLDefaultCryptoDBpath = # for DB used by Crypto Class
krypton.configs.SQLDefaultKeyDBpath =  # for DB used by Key Management System (you most likely don't need this)
krypton.configs.SQLDefaultUserDBpath = # for DB used by User Authentication System
```

## FIDO Auth

These configuration options must be set for FIDO (passwordless Auth) to work.

```python
krypton.configs.APP_NAME = "ExampleApp" # name of your app
krypton.configs.HOST_NAME = "example.com" # hostname, as seen by the user's browser
krypton.configs.ORIGIN = "https://exampel.com" # again, as seen by the user's browser
```
