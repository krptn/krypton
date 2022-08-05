# FIDO Passwordless

First make sure that the required configuration options for FIDO are set. See `FIDO Auth` section in [configurations](README-CONFIGS.md).

Currently, we only support passwordless as a second (or third) factor for authentication. The password still has to be enabled.

## Register

```python
options = model.beginFIDOSetup()
```

The above code generates options for FIDO. Please send these to the client's browser. In the browser, please run the following JS:

```html
<!---
    Some of this code was taken from Google's WebAuthn Glitch Tutorial: https://glitch.com/edit/#!/webauthn-codelab-start?path=README.md%3A1%3A0
    This code was changed to work with Krypton's Auth Backends. These include changing auth URLs, and base64 decoding.

    Here is the original copyright notice:

    Copyright 2019 Google Inc. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        https://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License
--->
<script src="https://cdn.jsdelivr.net/gh/herrjemand/Base64URL-ArrayBuffer@latest/lib/base64url-arraybuffer.js"></script>
<script>
    async function register() {
        const response = await fetch("/fidoReg", {});
        const options = await response.json();

        options.user.id = base64url.decode(options.user.id);
        options.challenge = base64url.decode(options.challenge);

        if (options.excludeCredentials) {
            for (let cred of options.excludeCredentials) {
                cred.id = base64url.decode(cred.id);
            }
        }

        const cred = await navigator.credentials.create({
            publicKey: options,
        });

        const credential = {};
        credential.id = cred.id;
        credential.rawId = base64url.encode(cred.rawId);
        credential.type = cred.type;

        if (cred.response) {
            const clientDataJSON =
                base64url.encode(cred.response.clientDataJSON);
            const attestationObject =
                base64url.encode(cred.response.attestationObject);
            credential.response = {
                clientDataJSON,
                attestationObject,
            };
        }
        localStorage.setItem(`KryptonFIDOcredId`, credential.id);
        return await fetch('fidoFinishReg/', credential);
    }
</script>
```

Inside inside `fidoFinishReg/` (or whatever you rename it to):

```python
import json
current_user.completeFIDOSetup(json.dumps(request.get_json()["credentials"])) # Of course, depending on your web framework this will differ
```

## Login
