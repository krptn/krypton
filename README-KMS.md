# Key Management System

This module uses a custom Key Management System for AES-256 keys.

You need to identify the key with a Name and a Password.

```python
from krypton.basic import KMS
obj = KMS()
key = obj.createNewKey("KeyName", "password")
keyAgain = obj.getKey("KeyName", "password")
## Note getKey raises a krypton.basic.KeyManagementError
# if the cryptoperiod of the key has expired as  
# specified in the config (config in README.md). To get the key
# anyway, add force=True to the parameters.
obj.removeKey("KeyName", "password")
```
