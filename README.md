![DevSkim Analysis](https://github.com/mbs9org/PySec/actions/workflows/CodeReview.yml/badge.svg) -> see security/result.sarif (plenty of false positives) for JSON representation (analysis by https://github.com/marketplace/actions/devskim). 

**Quick notice:** this project will be run for the Microsoft Imagine Cup. However, please use the project as you would otherwise. This warning is only for contributors who may not want there code to be used for such purposes. 

# PySec 
- Secure Storage of Data
- Authentication for Users
- Easy API
- FIPS Validated Cryptography (via OPENSSL)
- Planned User Authentication with OAuth integration

View aditional security mitigations: [Security Features](security/sec_feature_plan.md)

# Crypto 
```python
import pysec
# Before doing anything else, set the default location for the databases to be used. 
# Elsehow, it will be stores in site-packages/pysec-data.
# It should be a string to be passed to sqlalchemy to create an engine: https://docs.sqlalchemy.org/en/14/tutorial/engine.html
# See the above link to see what that is. Please also make sure to setup the required sql drivers for your server.
# Here are setup instructions for different servers: https://docs.sqlalchemy.org/en/14/dialects/index.html
# For example: "mssql+pyodbc://localhost/cryptoDB?driver=ODBC+Driver+18+for+SQL+Server"
pysec.configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///Path/example.db"
pysec.configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///Path/key.db"
# Create a instance of crypto - a class for encrypting and storing sensitive data.
myCrypto = pysec.basic.crypto()
# It supports C.R.U.D. operations:
id = myCrypto.secureCreate("Example data", 
    "Password - perhaps provided by the user") #id is an intiger
print("The data is", myCrypto.secureRead(id, 
        "Password - perhaps provided by the user"))
```

# User Auth
Being Developed

# Integration with web frameworks
To be made after User Auth 

# Optional: store keys in HSMs so Admin can decrypt user data
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