---
title: "Security Policy"
draft: false
date: "2022-10-14"
description: "Zero Knowledge security (as a IAM) for Python. This is our security policy."
---

## Supported Versions

Only the most recent version is supported; however, we are still interested in learning about security vulnerabilities in previous versions.

## Reporting a Vulnerability

### Vulnerabilitis affecting the Krptn module

If your vulnerability affects the code that is installed on peoples devices when they `pip install krptn`, please fill out [this form](https://github.com/krptn/krypton/security/advisories/new).

We also welcome vulnerabilities with no existing exploits. That means, for example, a use of an insecure cipher, that cannot be directly exploited, but is better fixed.

### Other vulnerabilites

If your vulnerability is not to do with the Python package (e.g.: XSS vulnerability on our website), please follow the below instructions.

Email security vulnerabilities to [security@krptn.dev](mailto:security@krptn.dev).

Please make sure the following information is clearly stated:

- What components are affected?
- PoC - if any (please see our below notice)
- Recommendations on fixes, if any

We also welcome vulnerabilities with no existing exploits. That means, for example, a use of an insecure cipher, that cannot be directly exploited, but is better fixed.

## Vulnerability Publishing

Any published vulnerabilities will be available under the Security tab of affected GitHub repositories. To view them, click on the tab and select advisories under the reporting section.

Important vulnerabilities will also appear under our news on our [homepage](https://www.krptn.dev/news/).

## GPG

Depending on the severity of the vulnerability, you might want to encrypt it with GPG/PGP before sending it.

Our key is uploaded to `pgp.mit.edu`, `keys.openpgp.org` and should be available on `keys.gnupg.net` (please use whichever you prefer), with a key id of `7126492594E7DCA0`. It is also copy-pasted into the bottom of this file.

(Please substitute "server" with your preferred server from the above mentioned)

```shell
gpg --keyserver server --recv-keys 7126492594E7DCA0
```

The following EC (nistp384, encrypt & sign) key was created on 2022-06-30 and expires on 2025-06-29:

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

mG8EYr2dPRMFK4EEACIDAwTc05svlFaiiWGCRxJ1FLdMJXXm1zRBn7XUnOm2AOUQ
SvOu0rpdnuLxDKMPFgBEerUk/wUkWC4SKA0UsaVRAFlaG8nwKTFJgWIMVjE6oNG2
qc5+pANQmtq3/pr2ktbANfa0aktyeXB0b25TdXBwb3J0IChUaGlzIGtleSBjYW4g
YmUgdXNlZCB0byBzZW5kIHNlbnNpdGl2ZSBpbmZvcm1hdGlvbiB0byBLcnlwdG9u
IFN1cHBvcnQpIDxzdXBwb3J0QGtycHRuLmRldj6IuQQTEwkAQRYhBHVHhK+OZb3q
W3WB6XEmSSWU59ygBQJivZ09AhsDBQkFo5qABQsJCAcCAiICBhUKCQgLAgQWAgMB
Ah4HAheAAAoJEHEmSSWU59ygzxsBgLqSADOF2ptNHftcQ1ZtPAY33gvLfN2rB6rF
fWH7GttqgWtd9Zcka+bgiqkrscdyXQGA2/fwKjxYu495FIMhnN555omRCKcLTRpi
/yoPKgRSqW7nFhW8llmJDY7QHYtg6i46iQIzBBABCAAdFiEEOT9Dt7NJPaH87PQJ
BwS8y6FfaRQFAmLP6hwACgkQBwS8y6FfaRQYMhAAgXTqvudNXG38eCJ6UMfdQug9
vEW1PL9f7Yq8mTa6hU2yJ8JZ1OH/YAeLPCIHBEnKC2XMYQ9X1hFKEpF4it3/KBVx
ZuRnIGY59Wp0cat8l6sRYLlIe4iw+fcTbhtEk8qCpbIXh09OzmwfbWFnX61mVdQC
7vgtZxWqZUfSJgRKpY/NGrENvvoyEQHqIZFeqJE5Bnnd2rj3QC7dyTx8eiQ+a3ZG
7Zw3TpXlc99a0t7L5upkvzZ7eKO6woh1NNN7VgXkHQ+GMCwEKsqdqT3jHt1uYimO
7CXrJPMtMnGEsvjMBeqRcVK8ge7je14x9p5j9nUEdXWo2g8oBC/4O87nEPzA78w2
CaYd/62OudLjV04mp4knKbHxKbBlZCtnGyOs/5NgpdM8jQWKsOnepbyGTtPKIhMQ
LEPM+JCIswtRtav+0QJQztrFQDFb174rl3gmNtseA60+SULmF77caboaqC5trDfn
YZHs3Zl800C55wY8v+tj2UgedWGYNKn4HUux3SAmNmVat/JE33bqYfsLrbcqV5z3
gK68nWjVfPAkLklQxywryXOFSfEnP9zBShiNjUmEWEY3KGYOqmo4q3X8Mo7mYRm6
bv+BT8ojmw8tDGBUNlcHqOqq/Q7nDyq782TKzbo2MgTCnpUNS4JLLV6is9/3RI1G
wX2jpX2YfzMOUOS9GUq4cwRivZ09EgUrgQQAIgMDBAloh4vRykF24nRdlsbB9aP5
RyGREr4VxxmR0LN+NcH2pUCaH8sYOK1Q75ki2Wgj8AdJ0uU5dyCWYHXQ7z7Ww60Z
4aN2u4d7KENBIxlUUMKD3zW12AHpabmB9ysrtSBfAgMBCQmIngQYEwkAJhYhBHVH
hK+OZb3qW3WB6XEmSSWU59ygBQJivZ09AhsMBQkFo5qAAAoJEHEmSSWU59yg25sB
gI8TP2MU1h5rIp1E7C1tJPahkq9YYVvhFX0JQ2xG2G/YuLVaLtqO+N+CoslnuNuA
OAGAqso7qKBIvidjN4jDdppBxPpEwYco+GLqjL29RwWz3MsdAfBtmGhEL3mUcqDq
dMF9
=x4k7
-----END PGP PUBLIC KEY BLOCK-----
```
