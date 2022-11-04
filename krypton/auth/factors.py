"""
Different Auth Factors available inside krypton.
"""
import os
import base64
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
    AuthenticationCredential,
)
from .. import base
from .. import configs

KEY_LEN = 32

class AuthFailed(Exception):
    """
    Exception to be raised when an error occures in a user model.
    """
    def __init__(self, *args: object) -> None:
        self.message = args[0]
        super().__init__()
    def __str__(self) -> str:
        return self.message

class password:
    """
    *Note:* no need to create an object just call the methods directly.
    Simple password authentication.

    1.) Hash the password with PBKDF2 and random salt.

    2.) Decrypt the value in the table arg.

    3.) Verify that the decryption was successfully authenticated.

    4.) Return the encryption key.
    """
    @staticmethod
    def getAuth(pwd:str):
        """Generate authentication tag for later use

        Arguments:
            pwd -- Password

        Returns:
            Auth tag
        """
        salt = os.urandom(12)
        key = base.PBKDF2(pwd, salt, keylen=KEY_LEN)
        text = os.urandom(12)
        authTag = f"{base.base64encode(base.restEncrypt(text, key))}${base.base64encode(salt)}${configs.defaultIterations}"
        return authTag

    @staticmethod
    def auth(authTag:str, pwd:str) -> bytes:
        """Authenticate against a tag

        Arguments:
            authTag -- Tag

            pwd -- Password

        Returns:
            Encryption key if success, False otherwise
        """
        splited = authTag.split("$")
        ctext, salt, iter = base.base64decode(splited[0]), base.base64decode(splited[1]), int(splited[2])
        key = base.PBKDF2(pwd, salt, iter, KEY_LEN)
        base.restDecrypt(ctext, key) # This raises an error if authentication fails.
        return key ## Success

class totp:
    """
    Simple TOTP authentication
    """
    @staticmethod
    def createTOTP(userName:str):
        """Create parameters for TOTP Generate

        Arguments:
            userName -- The username

        Returns:
            shared secret, base32 encoded shared secret, totp uri
        """
        secret = os.urandom(20)
        base32Secret = base64.b32encode(secret)
        return secret, base32Secret, base.createTOTPString(secret, userName)

    @staticmethod
    def verifyTOTP(secret:bytes, otp:str) -> bool:
        """Verify TOTP

        Arguments:
            secret -- The Shared secret
            otp -- The OTP

        Returns:
            True if success False otherwise
        """
        if not base.verifyTOTP(secret, otp):
            return False
        return True

class fido:
    """
    FIDO authentication support.
    """
    @staticmethod
    def register(userID:int, userName:str):
        """Start FIDO auth registration process

        Arguments:
            userID -- User's ID
            userName -- The User's username

        Returns:
            registration options and registration challenge
        """
        simple_registration_options = generate_registration_options(
            rp_id=configs.HOST_NAME,
            rp_name=configs.APP_NAME,
            user_id=str(userID),
            user_name=userName,
        )
        options = options_to_json(simple_registration_options)
        return options, simple_registration_options.challenge

    @staticmethod
    def register_verification(credentials, challenge):
        """Complete registration

        Arguments:
            credentials -- The user's fido credentials, recieved from the browser
            challenge -- The expected challenge

        Raises:
            AuthError: registration failure

        Returns:
            credential id and credential public key
        """
        registration_creds = RegistrationCredential.parse_raw(credentials)
        registration_verification = verify_registration_response(
            credential=registration_creds,
            expected_challenge=challenge,
            expected_origin=configs.ORIGIN,
            expected_rp_id=configs.HOST_NAME,
            require_user_verification=True,
        )
        success = registration_verification.credential_id == base64url_to_bytes(
            registration_creds.id
        )
        if success:
            return registration_verification.credential_id, registration_verification.credential_public_key
        raise AuthFailed("Cannot create registration for FIDO")

    @staticmethod
    def authenticate(cred_id):
        """Begin user authentication

        Arguments:
            cred_id -- The user's credential's id

        Returns:
            verification options, expected challange
        """
        authentication_options = generate_authentication_options(
            rp_id=configs.HOST_NAME,
            timeout=60000,
            user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=cred_id)],
        )
        options = options_to_json(authentication_options)
        return options, authentication_options.challenge

    @staticmethod
    def authenticate_verify(challenge:bytes, credential_public_key, credentials):
        """Complete Authentication

        Arguments:
            challenge -- The expected challange from authenticate
            credential_public_key -- The user's public key
            credentials -- The credentials provided by the user

        Returns:
            True on success, False otherwise
        """
        authentication_verification = verify_authentication_response(
            credential=AuthenticationCredential.parse_raw(credentials),
            expected_challenge=challenge,
            expected_rp_id=configs.HOST_NAME,
            expected_origin=configs.ORIGIN,
            credential_public_key=credential_public_key,
            credential_current_sign_count=0,
        )
        success = authentication_verification.new_sign_count > 0
        return success
