# FIDO Passwordless

*In order for this section to make sense, please read [User Auth](README-USER-AUTH.md) first.*

To see this implemented in action, you can have a look at our [Flask example](https://github.com/krptn/flaskExample).

First make sure that the required configuration options for FIDO are set. See `FIDO Auth & MFA` section in [configurations](README-CONFIGS.md).

Currently, we only support passwordless as a second (or third) factor for authentication. The password still has to be enabled.

We can only have one additional FIDO credentials registered. To revoke the current one:

```python
model.removeFIDO()
```

In adition, you may wish to remove from the browser, but it is fine to skip this:

```javascript
localStorage.removeItem('credId');
```

## Register

```python
options = model.beginFIDOSetup()
```

The above code generates options for FIDO. Please send these to the client's browser. In the browser, please run the following JS:

```html
<!---
    This code was taken from Google's WebAuthn Glitch Tutorial: https://glitch.com/edit/#!/webauthn-codelab-start?path=README.md%3A1%3A0
    This code was changed to work with Krypton's Auth Backends. These include changing auth URLs, loading JSON data.

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
        return await fetch('/fidoFinishReg', credential);
    }
</script>
```

Please see [Google's tutorial](https://developers.google.com/codelabs/webauthn-reauth) for more detail on the above code.

Inside inside `/fidoFinishReg` (or whatever you rename it to):

```python
import json
current_user.completeFIDOSetup(json.dumps(request.get_json()["credentials"])) # Of course, depending on your web framework this will differ
```

## Login

Before all we need to obtain our FIDO options:

```python
options = model.getFIDOOptions()
```

These will need to be transmited to the browser, and the result (returned from the browser) of the authentication should be passed to `login` function:

```python
model.login(pwd="MyPWD", fido=fidoResponse) # fidoResponse, is the stringified JSON from the browser.
```

On failure, a UserError will be raised and `model.FIDORequired` will be set to `True`.

To obtain authentication result in the browser:

```html
<!---
    Some of this code was taken from Google's WebAuthn Glitch Tutorial: https://glitch.com/edit/#!/webauthn-codelab-start?path=README.md%3A1%3A0
    This code was changed to work with Krypton's Auth Backends. These include changing auth URLs, loading JSON data.

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
<h3 class="title">You are required to use FIDO as an MFA.</h1>
<script src="https://cdn.jsdelivr.net/gh/herrjemand/Base64URL-ArrayBuffer@latest/lib/base64url-arraybuffer.js"></script>
<script>
    async function doFido() {
        const email = document.getElementsByName("email")[0].value; // Replace with your password form
        const pwd = document.getElementsByName("password")[0].value; // Replace with your password form
        const query = {}
        query.email = email;

        // To the below request, please return the response from model.getFIDOOptions()
        // Don't forget to replace your endpoint
        const repsonse = await fetch("/getFidoLogin", // Replace endpoint with yours 
            {cache: 'no-cache',
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(query)}
        );

        const options = await repsonse.json();

        options.challenge = base64url.decode(options.challenge);

        for (let cred of options.allowCredentials) {
            cred.id = base64url.decode(cred.id);
        }
        const cred = await navigator.credentials.get({
            publicKey: options
        });

        const credential = {};
        credential.fido = 1;
        credential.id = cred.id;
        credential.type = cred.type;
        credential.rawId = base64url.encode(cred.rawId);

        if (cred.response) {
            const clientDataJSON =
                base64url.encode(cred.response.clientDataJSON);
            const authenticatorData =
                base64url.encode(cred.response.authenticatorData);
            const signature =
                base64url.encode(cred.response.signature);
            const userHandle =
                base64url.encode(cred.response.userHandle);
            credential.response = {
                clientDataJSON,
                authenticatorData,
                signature,
                userHandle,
            };
        }
        const finalCredentials = JSON.stringify(credential);
        // Please pass `finalCredentials` as the `fido` parameter to the `login` function.
        // You still need to provide the user's password to the funcion also.
    }
</script>
```

Again, please see [Google's tutorial](https://developers.google.com/codelabs/webauthn-reauth) for more detail on the above code.
