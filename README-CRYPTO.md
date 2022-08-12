# Crypto Class

**⚠ Note:** Crypto Class is not thread-safe. Please create a new object to use in each thread!

Usage is dead simple. It automatically regenerates key after the number of years in pysec.configs.defaultCryptoperiod have passed.

```python
from krypton.basic import Crypto

cryptoObject = Crypto()
id = cryptoObject.secureCreate("data", "pwd") # returns an integer
print("Reading data:")
print(cryptoObject.secureRead(id, "pwd")) # Prints data

print("Updating data:")
cryptoObject.secureUpdate(id, "New Data", "pwd")
print(cryptoObject.secureRead(id, "pwd")) # Prints New Data

print("Deleting:")
cryptoObject.secureDelete(id, "pwd")
```
