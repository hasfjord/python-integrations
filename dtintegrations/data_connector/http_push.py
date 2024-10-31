import jwt
import json
import hashlib
import requests
from typing import Any, Optional

import disruptive  # type: ignore

from dtintegrations import request as dtrequest, outputs
from dtintegrations.data_connector import metadata as metadata


class HttpPush(outputs.OutputBase):
    """
    Represents the HTTP Push Data Connector at the receiver side.

    Attributes
    ----------
    event : Event
        An object representing the received event.
    labels : dict
        Labels from the source device forwarded by the Data Connector.

    """
    def __init__(
        self,
        headers: dict,
        body: bytes,
        secret: str = '',
        org_id: str = '',
        oidc_config_uri: str = (
            'https://identity.disruptive-technologies.com/'
            'data-connector/.well-known/openid-configuration'
        )
    ):
        """
        Constructs the HttpPush object given request contents.

        """

        self._headers = headers
        self._body = body
        self._secret = secret
        self._org_id = org_id
        self._oidc_config_uri = oidc_config_uri

        self._body_dict = self._decode(headers, body, secret)
        super().__init__(self._body_dict)

        self.event = disruptive.events.Event(self._body_dict['event'])
        self.labels = self._body_dict['labels']
        self._metadata_dict = self._body_dict['metadata']

    def __repr__(self) -> str:
        string = '{}.{}('\
            'headers={},'\
            'body={},'\
            'secret={},'\
            'org_id={},'\
            'oidc_config_uri={}'\
            ')'
        return string.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self._headers,
            self._body,
            repr(self._secret),
            repr(self._org_id),
            repr(self._oidc_config_uri),
        )

    def get_device_metadata(self) -> Optional[metadata.DeviceMetadata]:
        """
        Fetch source device metadata if it exists.

        Returns
        -------
        metadata : DeviceMetadata, optional
            An object representing the source device metadata.
            If the event forwarded by the Data Connector does not originate
            a device, DeviceMetadata returns None.
        """

        try:
            return metadata.DeviceMetadata(self._metadata_dict)
        except KeyError:
            return None

    def _decode(self, headers: dict, body: bytes, secret: str = '') -> dict:
        """
        Decodes the incoming event, first validating the source- and origin
        using a signature secret and the request header- and body.

        Parameters
        ----------
        headers : dict[str, str]
            Headers key- value pairs in request. For multi-header
            format, the value should be a comma-separated string.
        body : bytes
            Request body bytes.
        secret : str
            The secret to sign the request at source.

            Deprecated:
            This is now deprecated in favor of the
            X-DT-JWT-Assertion header.
            The secret is no longer required.

        Returns
        -------
        payload : HttpPush
            An object representing received HTTP Push Data Connector payload.

        Raises
        ------
        ConfigurationError
            If any of the input parameters are of invalid type, or
            the signature secret is expired.

        """

        # Isolate the token in request headers.
        custom_token = None
        token = None
        for key in headers:
            if key.lower() == 'x-dt-signature':
                custom_token = headers[key]
            if key.lower() == 'dt-asymmetric-signature':
                token = headers[key]

        # Calculate the body SHA-256 checksum.
        m = hashlib.sha256()
        m.update(body)
        checksum_sha256 = m.digest().hex()

        # Validate the custom token if it exists.
        if custom_token:
            self._validate_custom_token(custom_token, checksum_sha256, secret)

        # Validate the DT Data Connector token.
        if token:
            self._validate_dt_token(token, checksum_sha256)
        else:
            raise disruptive.errors.ConfigurationError(
                'No Data Connector token found.'
            )

        # Convert the body bytes string into a dictionary.
        body_dict = json.loads(body.decode('utf-8'))

        return dict(body_dict)

    def _validate_dt_token(self, token: str, checksum: str) -> None:
        """
        Validates the Data Connector token using the signature secret.

        Parameters
        ----------
        token : str
            The token to validate.
        checksum : str
            The SHA-256 checksum of the request body.

        Raises
        ------
        ConfigurationError
            If the token is invalid, expired, or the checksum does not match,
            or if is not signed by DTs OIDC provider.

        """

        try:
            oidc_config = requests.get(self._oidc_config_uri).json()
        except requests.exceptions.RequestException:
            raise disruptive.errors.ConfigurationError(
                'Failed to fetch OIDC configuration.'
            )
        except json.JSONDecodeError:
            raise disruptive.errors.ConfigurationError(
                'Failed to parse OIDC configuration.'
            )

        # Decode the token using the JWK client.
        try:
            jwks_client = jwt.PyJWKClient(
                oidc_config['jwks_uri'], cache_jwk_set=True
            )
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=oidc_config[
                    'id_token_signing_alg_values_supported'
                ],
                issuer=oidc_config['issuer'],
                options={
                    'verify_signature': True,
                    'verify_iss': True,
                    'verify_exp': True,
                    'verify_iat': True,
                }
            )
        except jwt.exceptions.InvalidSignatureError:
            raise disruptive.errors.ConfigurationError(
                'Invalid signature.'
            )
        except jwt.exceptions.ExpiredSignatureError:
            raise disruptive.errors.ConfigurationError(
                'Signature has expired.'
            )
        except jwt.exceptions.InvalidIssuerError:
            raise disruptive.errors.ConfigurationError(
                'Invalid issuer: {}'.format(payload['iss'])
            )
        except jwt.exceptions.InvalidAlgorithmError:
            raise disruptive.errors.ConfigurationError(
                'Invalid algorithm.'
            )
        if self._org_id and payload['sub'] != self._org_id:
            raise disruptive.errors.ConfigurationError(
                'Invalid subject, should match the organization ID.'
            )

        # Calculate and compare the body SHA-256 checksum.
        if payload['checksum_sha256'] != checksum:
            raise disruptive.errors.ConfigurationError(
                'Checksum mismatch.'
            )

    @staticmethod
    def _validate_custom_token(token: str, checksum: str, secret: str) -> None:
        """
        Validates the custom token using the signature secret.

        Parameters
        ----------
        token : str
            The token to validate.
        body : bytes
            The request body bytes.
        secret : str
            The secret to sign the token at source.

        Raises
        ------
        ConfigurationError
            If the token is invalid, expired, or the checksum does not match,
            or if the secret does not match the token signature.

        """

        # Decode the token using the signature secret.
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=['HS256'],
            )
        except jwt.exceptions.InvalidSignatureError:
            raise disruptive.errors.ConfigurationError(
                'Invalid secret.'
            )
        except jwt.exceptions.ExpiredSignatureError:
            raise disruptive.errors.ConfigurationError(
                'Signature has expired.'
            )

        # Calculate and compare the body SHA-256 checksum.
        if payload['checksum_sha256'] != checksum:
            raise disruptive.errors.ConfigurationError(
                'Checksum mismatch.'
            )

    @staticmethod
    def from_provider(
            request: Any,
            provider: str,
            secret: str = '',
            org_id: str = '',
            oidc_config_uri: str = (
            'https://identity.disruptive-technologies.com/'
            'data-connector/.well-known/openid-configuration'
            ),
    ) -> Any:
        """
        Decodes the incoming event using a specified provider, first validating
        the the source- and origin using a signature secret
        and the provider-specific request.

        Parameters
        ----------
        request : Any
            Unmodified incoming request format of the specified provider.
        provider : {"flask", "gcloud", "lambda", "azure"}, str
            Name of the :ref:`provider <integrations_provider>`
            used to receive the request.
        secret : str
            The secret to sign the request at source.

        Returns
        -------
        payload : HttpPush
            An object representing received HTTP Push Data Connector payload.

        Raises
        ------
        ConfigurationError
            If any of the input parameters are of invalid type, or
            the signature secret is expired.

        """

        # Create a Request instance of the provider used for MISO.
        r = dtrequest.Request(request, provider)

        # Use a more generic function for the validation process.
        return HttpPush(
            r.headers,
            r.body_bytes,
            secret,
            org_id=org_id,
            oidc_config_uri=oidc_config_uri,
        )
