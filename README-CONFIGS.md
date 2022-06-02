# Configuration

**Note:** a change in settings will not result in decryption and re-encryption of data to apply the settings. Instead they are applied when new data is encrypted or modified - thereby slowly phasing out the old configuration. 

Simple, pythonic configuration:
```python
import pysec

pysec.defaultAlgorithm = "exmaple: AES256GCM" # Sets which symetric cipher to use (currently only AES256GCM is supported)

pysec.defaultIterations = 600000 # Number of iterations for PBKDF2

pysec.defaultCryptoperiod = 2 # Approx. Number of years for the cryptoperiod of a key
```

For the following settings please see [Databases](README-DATABASES.md) 

```python
pysec.configs.SQLDefaultCryptoDBpath = # for DB used by Crypto Class
pysec.configs.SQLDefaultKeyDBpath =  # for DB used by Key Management System (you most likely don't need this)
pysec.configs.SQLDefaultUserDBpath = # for DB used by User Authentication System 
```
