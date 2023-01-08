# Contributing

## Scope of the Project

The scope of this project is an IAM, with the extra feature of encryption of any data.

## Conventions

Naming conventions:

- We use camelCase conevention for attributes, variables, and function names.
- PascalCase for class names.
- UPPER_CASE for constants
- Variables starting in _ or __ are not to be accessed directly by the users - they are internals.
- In databases, names starting in _ or __ should only store data required by us - no user data, they are internals.

## Build/Setup the extension for development

First, please build from the git repository as outlined in [our documentation](https://docs.krptn.dev/README-BUILD.html#building-from-source).

For development use, it is probably a good idea to install the extension in editable mode (i.e setuptools "develop mode"):

```shell
pip install -e .
```

To rebuild __CryptoLib extension with debugging symbols:

```shell
python setup.py build_ext --debug --inplace
```
