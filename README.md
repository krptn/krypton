![DevSkim Analysis](https://github.com/mbs9org/PySec/actions/workflows/CodeReview.yml/badge.svg) -> see security/result.sarif (plenty of false positives) for JSON representation (analysis by https://github.com/marketplace/actions/devskim). 

# PySec: An API which provides the following
- Secure Storage of Data
- Secure Storage of keys: HSMs, etc...
- Authentication
- ML/AI to detect attacks - not developed yet 

View aditional security mitigations: [Security Features](security/sec_feature_plan.md)

# Example: 
```python
import pysec
# Before doing anything else, set the default location for the databases to be used. 
# Elsehow, it will be stores in site-packages/pysec-data.
# There is no need to create the databses: pysec will do that for you.
pysec.cryptoDBLocation = "Path/example.db"
pysec.altKeyDB = "Path/key.db"
# Create a instance of crypto - a class for encrypting and storing sensitive data.
myCrypto = pysec.basic.crypto()
# It supports C.R.U.D. operations:
id = myCrypto.secureCreate("Example data", "Password - perhaps provided by the user") #id is an intiger
print("The data is",
    myCrypto.secureRead(id, "Password - perhaps provided by the user"))
```

# Settings 

# Build/Setup the extension: 
First please build and install openssl3 before building pysec. Currently only windows is supported. Please install openssl in the /openssl-install and place configs in /openssl-config directory (where /openssl-install and /openssl-config is in the root folder of this repo). Hence, when using perl Configure please pass --prefix=DIR (replace dir with your /openssl-install directory), --openssldir=DIR (replace DIR with your /openssl-config directory) and enable-fips option. 
To create debug binaries, you need to pass the --debug option also. 

For example (Windows example): 
```shell 
perl Configure --prefix="C:\Users\trans\source\repos\PySec\openssl-install" --openssldir="C:\Users\trans\source\repos\PySec\openssl-config" enable-fips --debug
```

To install the extension and produce debuging symbols use: 
```shell
python setup.py build_ext --debug
pip install .
pip install -e .
```

To install the extension and not produce debuging symbols:
```shell
pip install . 
```