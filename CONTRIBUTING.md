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

## Build/Setup the extension for development, Build from source

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
