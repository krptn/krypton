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

```python
import PySec
```
# Build/Setup the extension: 
First please build openssl in the /openssl directory acording to their instructions. Also install the fips_module. 
