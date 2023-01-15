![Apache-2.0](https://img.shields.io/pypi/l/Krptn)
![Downloads](https://static.pepy.tech/personalized-badge/krptn?period=total&units=international_system&left_color=blue&right_color=orange&left_text=PyPI%20Downloads)
[![Last Release status](https://github.com/krptn/krypton/actions/workflows/release.yml/badge.svg?event=release)](https://github.com/krptn/krypton/actions/workflows/release.yml)

# Krptn

```shell
pip install krptn
```

## What problem do we solve?

**We all love Django and other web frameworks!** However, their primary focus is creating websites - not securing them. One example is Django's built-in authentication system. While it hashes the password, it does not encrypt user data for you. Encryption is left to the developer...

**Wouldn't it be nice if encryption would also be handled by the IAM?** Perhaps it could be handled in a zero knowledge model, such that, without the user entering credentials, not even the database administrator can read it?! This is exactly what we do! Please see our [documentation](https://docs.krptn.dev/index.html), [homepage](https://www.krptn.dev/) or continue here, on our GitHub, for more information!

**To prove that such is possible, we have a [Flask](https://github.com/krptn/flaskExample) and [Django](https://github.com/krptn/djangoExample) example on GitHub.**

![Krptn Visual](https://www.krptn.dev/krptnDiagram.webp)

## What do we do exactly?

We are building a user authentication and access management system (IAM) with [Zero Knowledge security](https://www.krptn.dev/news/zero-knowledge/). It is available as a python extension module. However we have certain [limitations](https://www.krptn.dev/news/limitations/).

How we achieve this?

- All data is encrypted (any data can be requested by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem (this protects you from server-side attacks)

This gives you [Zero Knowledge security](https://www.krptn.dev/news/zero-knowledge/) (one of the most secure available) without ever needing to even notice it! It protects you from server side attacks.

## Features

- Secure Storage of Data
- User Authentication
- FIPS Validated Cryptography (via OpenSSL 3)*
- Secure memory wiping (except on PyPy)
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
dataId = myCrypto.secureCreate("Example data", pwd) #id is an integer
print("The data is:")
print(myCrypto.secureRead(dataId, pwd)) # prints Example data
```

## User Auth

See [User Auth](https://docs.krptn.dev/README-USER-AUTH.html).

To use FIDO with User Auth, please see [Krptn's FIDO Documentation](https://docs.krptn.dev/README-FIDO.html).

## Integration with web frameworks

- [Django](https://docs.krptn.dev/README-DJANGO.html)
- [Flask](https://docs.krptn.dev/README-FLASK.html)

## Crypto Class

[Crypto Class](https://docs.krptn.dev/README-CRYPTO.html)

## Key Management System

This module uses a custom Key Management System for AES-256 Keys.
See [KMS](https://docs.krptn.dev/README-KMS.html) for more information.

**Note:** we have considered using HSM as key management systems. We, however, have decided that we will not integrate HSMs because it would be difficult to maintain Zero Knowledge security.

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

We would love to learn how you use our project! Our email is [contact@krptn.dev](mailto:contact@krptn.dev), and we would appreciate if you could drop us a note about your interactions with Krptn.

## Stargazers

![Stargazers for @Krptn/Krypton](https://reporoster.com/stars/krptn/krypton)
