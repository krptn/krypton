# Contributing

## Scope of the Project

The scope of this project is an IAM, which ensures proper encryption of any data.

## Conventions

Naming conventions:

- We use camelCase conevention for attributes, variables, and function names.
- PascalCase for class names.
- UPPER_CASE for constants
- Variables starting in _ or __ are not to be accessed directly by the users - they are internals.
- In databases, names starting in _ or __ should only store data required by Krypton - no user data, they are internals.

## Important Warnings

Our base64 encoding and decoding is unique. This means that data base64 encoded here may not be decodable elsewhere. **Additionally, decoding is suspectable to buffer overflow (but it cannot be exploited for remote code execution, it can only trigger errors).** Hence, do not ever base64 decode using `base.base64decode` from an untrusted source. For that use python's base64 decoding module.

## Build/Setup the extension for development, Build from source

*Note:* apart from x86 on Windows, only 64-bit environments are supported.

After cloning the repo (and checking out your version using git tags), please build and install OpenSSL 3, which is included as a git submodule:

- Install openssl in the `kr-openssl-install/` and place configurations in `kr-openssl-config/` directories.
  - Therefore, in the configure script, you need `--prefix` and `--openssldir` set.
- As Krypton uses FIPS, please set `enable-fips` also.

For example (Windows example):

```shell
perl Configure --prefix="C:\Users\markb\source\repos\krypton\kr-openssl-install" \
  --openssldir="C:\Users\markb\source\repos\krypton\kr-openssl-config" \
  enable-fips --debug
```

You need to both build and install OpenSSL:

```shell
make
make install
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
