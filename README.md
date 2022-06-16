**Quick notice:** this project will be run for the Microsoft Imagine Cup. However, please use the project as you would otherwise. This warning is only for contributors who may not want there code to be used for such purposes.

# What is this?

A user authentication and access management system based entirely on cryptographic primitives.

What we mean by that is:
- All Data is encrypted (any data can be request by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem

# PySec
- Secure Storage of Data
- Authentication for Users
- Easy API
- FIPS Validated Cryptography (via OPENSSL)
- Planned User Authentication with OAuth integration
- Planned integration with popular web frameworks

View aditional security mitigations: [Security Features](security/sec_feature_plan.md)

### Example usage of the Crypto Class:
```python
from pysec import basic
# Create a instance of Crypto - a class for encrypting and storing sensitive data.
myCrypto = basic.Crypto()
pwd = "Perhaps provided by the user"
# It supports C.R.U.D. operations:
id = myCrypto.secureCreate("Example data", pwd) #id is an intiger
print("The data is:")
print(myCrypto.secureRead(id, pwd)) # prints Example data
```

# User Auth
Being Developed

# Integration with web frameworks
To be made after User Auth

# Crypto Class
[Crypto Class](README-CRYPTO.md)

# Key Management System
This module uses a custom Key Management System that aims to conform to all NIST Recomendations. This contains a low-level interface and is not recomended to be called directly: it's primary purpose is to help other high-level interfaces.

# Use custom databases
Here is an example for how to set the database to be used:
```python
import pysec
pysec.configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///Path/example.db"
pysec.configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///Path/key.db"
```
To see what these strings should contain please see [Databases](README-DATABASES.md)

# Settings
[Configurations](README-CONFIGS.md)

# Optional: store keys in HSM
After integrations with web frameworks

# Build/Setup the extension for development
First please build and install openssl3 before building pysec. Currently only windows is supported. Please install openssl in the /openssl-install and place configs in /openssl-config directory (where /openssl-install and /openssl-config is in the root folder of this repo). Hence, when using perl Configure please pass --prefix=DIR (replace dir with your /openssl-install directory), --openssldir=DIR (replace DIR with your /openssl-config directory) and enable-fips option.
To create debug binaries, you need to pass the --debug option also.

For example (Windows example):
```shell
perl Configure --prefix="C:\Users\markb\source\repos\PySec\openssl-install" --openssldir="C:\Users\markb\source\repos\PySec\openssl-config" enable-fips --debug
```

To install the extension and produce debuging symbols use:
```shell
pip install -e .
python setup.py build_ext --debug --inplace
```
To rebuild the extension (e.g: you made changes to the code), only run the second command.

To install the extension and not produce debuging symbols:
```shell
pip install .
```

# Planned:
- APIs for other languages
- Premium features