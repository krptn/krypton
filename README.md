![DevSkim Analysis](https://github.com/mbs9org/PySec/actions/workflows/CodeReview.yml/badge.svg) -> see security/result.sarif (plenty of false positives) for JSON representation (analysis by https://github.com/marketplace/actions/devskim). 

# PySec: An API which provides the following
- Secure web server: TLS and Authentication for users. 
- Secure Storage of Data
- Secure Storage of keys: HSMs, etc...
- Authentication and access managment 
- Handels sensitive data for the developer: so the developer can have a piece of mind that the data is safe
- ML/AI to detect attacks - not developed yet 
# It does this all automatically: so the developers can focus on their work, and PySec does the security. 
View security features: [Security Features](security/sec_feature_plan.md)
# It provides a distributed settings network where a change to a setting on one device is synced to others (by signing with admins key) - not developed yet. 
```python
import PySec
```
# Build/Setup the extension: 
First please build and install openssl3 before building pysec. Currently only windows is supported. Please install openssl in the /openssl-install and place configs in /openssl-config directory (where /openssl-install and /openssl-config is in the root folder of this repo). 

So when using Configure please pass --prefix=DIR (replace dir with your /openssl-install directory), --openssldir=DIR (to your /openssl-config directory) and enable-fips option. 

For example: 
```shell 
perl Configure --prefix="C:\Users\MARKBA~1\source\repos\PySec\openssl-install" --openssldir="C:\Users\MARKBA~1\source\repos\PySec\openssl-config" enable-fips 
```
