# Krypton

Please see our [documentation](https://docs.krptn.dev/index.html).

**Quick Install:**

```shell
pip install krptn
```

## What is this?

**Quick notice:** this project will be run for the Microsoft Imagine Cup. However, please use the project as you would otherwise. This warning is only for contributors who may not want their code to be used for such purposes.

A user authentication and access management system based entirely on cryptographic primitives. It is available as a python extension module.

What we mean by that is:

- All Data is encrypted (any data can be request by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem (this protects you from server-side attacks)

This gives you [Zero Knowledge security](https://www.krptn.dev/news/zero-knowledge/) (one of the most secure available) without ever needing to even notice it! It protects you from server side attacks.

## Features

- Secure Storage of Data
- User Authentication
- FIPS Validated Cryptography (via OPENSSL3)*
- Secure memory wiping
- FIDO Passwordless*
- Integration with popular web frameworks

\* FIDO (passwordless) does not use FIPS validated resolvers

### Example usage of the Crypto Class

```python
from krypton import basic
# Create an instance of Crypto - a class for encrypting and storing sensitive data.
myCrypto = basic.Crypto()
pwd = "Perhaps provided by the user"
# It supports C.R.U.D. operations:
id = myCrypto.secureCreate("Example data", pwd) #id is an integer
print("The data is:")
print(myCrypto.secureRead(id, pwd)) # prints Example data
```

## User Auth

See [User Auth](https://docs.krptn.dev/README-USER-AUTH.html).

To use FIDO with user auth, please see [Krypton's FIDO Documentation](https://docs.krptn.dev/README-FIDO.html) (but please read📖 [user auth](https://docs.krptn.dev/README-USER-AUTH.html) first).

## Integration with web frameworks

- [Django](https://docs.krptn.dev/README-DJANGO.html) - Not implemented yet.
- [Flask](https://docs.krptn.dev/README-FLASK.html)

## Crypto Class

[Crypto Class](https://docs.krptn.dev/README-CRYPTO.html)

## Key Management System

This module uses a custom Key Management System for AES-256 Keys.
See [KMS](https://docs.krptn.dev/README-KMS.html) for more information.

**Note:** we have considered using HSM as key management systems. However, we have decided that we will not implement HSMs because it would not be possible to withhold that cryptographic systems are only unlocked with correct credentials: this is because a HSM would happily provide the key to Krypton irrespective of whether the user of the web app has provided credentials.

Of course, all data is securely encrypted even if it is not via a HSM!

If you want, you can encrypt the SQL database using HSM managed keys for additional security.

## Use custom databases

Here is an example for how to set the database to be used:

```python
import krypton
krypton.configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///Path/example.db"
krypton.configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///Path/key.db"
```

To see what these settings strings should contain please see [Databases](https://docs.krptn.dev/README-DATABASES.html).

## Settings

[Configurations](https://docs.krptn.dev/README-CONFIGS.html)

## Build/Setup the extension for development

*Note:* currently only 64-bit environments have been tested.

After cloning the repo, please build and install openssl3. Please install openssl in the /kr-openssl-install and place configs in /kr-openssl-config directory (where /kr-openssl-install and /kr-openssl-config is in the root folder of this repo). Hence, when using perl Configure please pass --prefix=DIR (replace dir with your /kr-openssl-install directory), --openssldir=DIR (replace DIR with your /kr-openssl-config directory) and enable-fips option.
To create debug binaries, you need to pass the --debug option also.

For example (Windows example):

```shell
perl Configure --prefix="C:\Users\markb\source\repos\krypton\kr-openssl-install" \
  --openssldir="C:\Users\markb\source\repos\krypton\kr-openssl-config" \
  enable-fips --debug
```

To install the extension and produce debugging symbols use:

```shell
pip install -e .
python setup.py build_ext --debug --inplace
```

To rebuild __CryptoLib extension, only run the second command.

To install the extension and not produce debugging symbols:

```shell
pip install .
```

## Planned

- APIs for other languages
- Premium features
