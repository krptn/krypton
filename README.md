![Apache-2.0](https://img.shields.io/pypi/l/Krptn)
![Downloads](https://static.pepy.tech/personalized-badge/krptn?period=total&units=international_system&left_color=blue&right_color=orange&left_text=PyPI%20Downloads)
[![Last Release status](https://github.com/krptn/krypton/actions/workflows/release.yml/badge.svg?event=release)](https://github.com/krptn/krypton/actions/workflows/release.yml)
![codecov](https://codecov.io/gh/krptn/krypton/branch/master/graph/badge.svg?token=AQPVJXQLRP)

We also have a [homepage](https://www.krptn.dev/) and [documentation](https://docs.krptn.dev/index.html) for you to check out.

# Krptn

```shell
pip install krptn
```

## What problem do we solve?

**We all love Django and other web frameworks!** However, their primary focus is creating websites - not implementing secure storage for user data. Django makes it easy to store data. While it hashes the password, it does not encrypt user data for you. In case of a data breach, malicious actors could access any data from the DB. Encryption is left to the developer...

**Wouldn't it be nice if encryption would also be handled?** Perhaps it could be handled in a **[way that keys are derived from credentials](https://www.krptn.dev/news/zero-knowledge/)**, such that, without the user entering credentials, not even the database administrator can read it?! This is exactly what we do!

**We also handle user authentication, including MFA, and passwordless authentication.**

**Krptn also runs in the same server instance** as your web app. So you don't have to host anything new. Just install the extension for Python.

**To prove that such is possible, we have a [Flask](https://github.com/krptn/flaskExample) and [Django](https://github.com/krptn/djangoExample) example on GitHub.**

## What do we do exactly?

We are building a user authentication and access management system (IAM) with **[data encryption at rest derived from credentials](https://www.krptn.dev/news/zero-knowledge/)**. It is available as a python extension module. However we have certain [limitations](https://www.krptn.dev/news/limitations/).

How we achieve this?

- All data is encrypted (any data can be requested by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem (this protects you from server-side attacks)

This gives you *[security from encryption](https://www.krptn.dev/news/zero-knowledge/)* without ever needing to even notice it! It protects you from server side attacks.

Here is an example usage:

```python
from krypton.auth.users import userModel

model = userModel.standardUser(None)
model.saveNewUser("Test_UserName", "Test_Password")
model.data.email = "test@example.com" # The email will be encrypted, and securely stored
```

![Krptn Visualisation](https://www.krptn.dev/krptnDiagram.webp)

## Try it out

Quickly install the package with pip for Python>3.9:

```shell
pip install krptn
```

Have a look at our [User Authentication documentation](https://docs.krptn.dev/README-USER-AUTH.html), and create some users.

Ready to integrate it into your WebApp? Have a look at some of our integration's available with [Django and Flask](https://docs.krptn.dev/README.html#integration-with-web-frameworks)!
