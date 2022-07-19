# Krypton

To see this documentation as a website, please see [documentation](https://docs.krptn.dev/index.html).

## What is this?

**Quick notice:** this project will be run for the Microsoft Imagine Cup. However, please use the project as you would otherwise. This warning is only for contributors who may not want there code to be used for such purposes.

A user authentication and access management system based entirely on cryptographic primitives.

What we mean by that is:

- All Data is encrypted (any data can be request by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem

## Features

- Secure Storage of Data
- Authentication for Users
- Easy API
- FIPS Validated Cryptography (via OPENSSL3)
- Planned User Authentication with OAuth integration
- Planned integration with popular web frameworks

### Example usage of the Crypto Class

```python
from krypton import basic
# Create a instance of Crypto - a class for encrypting and storing sensitive data.
myCrypto = basic.Crypto()
pwd = "Perhaps provided by the user"
# It supports C.R.U.D. operations:
id = myCrypto.secureCreate("Example data", pwd) #id is an intiger
print("The data is:")
print(myCrypto.secureRead(id, pwd)) # prints Example data
```

## User Auth

See [User Auth](README-USER-AUTH.md). Please see [integrations](#Integration-with-web-frameworks) to use user authentication with supported web frameworks.

## Integration with web frameworks

- [Django](README-DJANGO.md)
- [Flask](README-FLASK.md)

## Crypto Class

[Crypto Class](README-CRYPTO.md)

## Key Management System

This module uses a custom Key Management System for AES-256 Keys.
See [KMS](README-KMS.md) for more information.

## Use custom databases

Here is an example for how to set the database to be used:

```python
import krypton
krypton.configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///Path/example.db"
krypton.configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///Path/key.db"
```

To see what these strings should contain please see [Databases](README-DATABASES.md)

## Settings

[Configurations](README-CONFIGS.md)

## Optional: store keys in HSM

After integrations with web frameworks

## Build/Setup the extension for development

*Note:* currently only 64-bit environments have been tested.

First please build and install openssl3 before building krypton. Please install openssl in the /kr-openssl-install and place configs in /kr-openssl-config directory (where /kr-openssl-install and /kr-openssl-config is in the root folder of this repo). Hence, when using perl Configure please pass --prefix=DIR (replace dir with your /kr-openssl-install directory), --openssldir=DIR (replace DIR with your /kr-openssl-config directory) and enable-fips option.
To create debug binaries, you need to pass the --debug option also.

For example (Windows example):

```shell
perl Configure --prefix="C:\Users\markb\source\repos\krypton\kr-openssl-install" \
  --openssldir="C:\Users\markb\source\repos\krypton\kr-openssl-config" \
  enable-fips --debug
```

To install the extension and produce debuging symbols use:

```shell
pip install -e .
python setup.py build_ext --debug --inplace
```

To rebuild __CryptoLib extension, only run the second command.

To install the extension and not produce debuging symbols:

```shell
pip install .
```

## Planned

- APIs for other languages
- Premium features
