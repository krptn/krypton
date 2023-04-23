![Apache-2.0](https://img.shields.io/pypi/l/Krptn)
![Downloads](https://static.pepy.tech/personalized-badge/krptn?period=total&units=international_system&left_color=blue&right_color=orange&left_text=PyPI%20Downloads)
[![Last Release status](https://github.com/krptn/krypton/actions/workflows/release.yml/badge.svg?event=release)](https://github.com/krptn/krypton/actions/workflows/release.yml)

# Krptn

```shell
pip install krptn
```

## What problem do we solve?

**We all love Django and other web frameworks!** However, their primary focus is creating websites - not implementing secure storage for user data. One example is Django's built-in authentication system. While it hashes the password, it does not encrypt user data for you. Encryption is left to the developer...

**Wouldn't it be nice if encryption would also be handled?** Perhaps it could be handled in a zero knowledge model, such that, without the user entering credentials, not even the database administrator can read it?! Maybe it could even use FIPS validated cryptography. This is exactly what we do!

**To prove that such is possible, we have a [Flask](https://github.com/krptn/flaskExample) and [Django](https://github.com/krptn/djangoExample) example on GitHub.**

![Krptn Visual](https://www.krptn.dev/krptnDiagram.webp)

## What do we do exactly?

We are building a user authentication and access management system (IAM) with [Zero Knowledge security](https://www.krptn.dev/news/zero-knowledge/). It is available as a python extension module. However we have certain [limitations](https://www.krptn.dev/news/limitations/).

How we achieve this?

- All data is encrypted (any data can be requested by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem (this protects you from server-side attacks)

This gives you [Zero Knowledge security](https://www.krptn.dev/news/zero-knowledge/) without ever needing to even notice it! It protects you from server side attacks.

## Try it out

Quickly install the package with pip for Python>3.9:

```shell
pip install krptn
```

Have a look at our [User Authentication documentation](https://docs.krptn.dev/README-USER-AUTH.html), and create some users.

Ready to integrate it into your WebApp? Have a look at some of our integration's available with [Django and Flask](https://docs.krptn.dev/README.html#integration-with-web-frameworks)!

## Stargazers

![Stargazers for @Krptn/Krypton](https://reporoster.com/stars/krptn/krypton)
