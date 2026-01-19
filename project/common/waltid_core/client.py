from typing import Optional
import httpx
from common import config
from .session import  WaltIdSession
from .errors import WaltIdError, WaltIdHttpError

# ===================
# CONFIG
cfg = config()

BASE_URL = cfg["waltid"]["base_url"]
REGISTER_ENDPOINT = cfg["waltid"]["register_endpoint"]
LOGIN_ENDPOINT = cfg["waltid"]["login_endpoint"]
WALLETID_ENDPOINT = cfg["waltid"]["walletID_endpoint"]
CREDENTIALS_TEMPLATE = cfg["waltid"]["credentials_endpoint"]
KEYS_ENDPOINT_TEMPLATE = cfg["waltid"]["keys_endpoint"]
KEY_EXPORT_TEMPLATE = cfg["waltid"]["key_export_endpoint"]
DEFAULT_DID_TEMPLATE = cfg["waltid"]["default_did_endpoint"]
MATCH_CREDS_TEMPLATE = cfg["waltid"]["match_creds_endpoint"]
CRED_ID_TEMPLATE = cfg["waltid"]["credential_id_endpoint"]
# ===================

class WaltIdClient:
    _client: Optional[httpx.AsyncClient] = None

    @classmethod
    def _get_client(cls) -> httpx.AsyncClient:
        """
        Retrieves and initializes an asynchronous HTTP client for making requests.

        Creates a new instance of `httpx.AsyncClient` if no client exists or the
        existing client is closed. The client is configured with a predefined
        base URL and timeout value.

        Returns:
            httpx.AsyncClient: The asynchronous HTTP client instance.
        """
        if cls._client is None or cls._client.is_closed:
            cls._client = httpx.AsyncClient(
                base_url=BASE_URL,
                timeout=15.0,
            )
        return cls._client

    @classmethod
    async def cleanup(cls):
        """
        Cleans up client resources by closing the connection if active.

        This method checks if the client resource is initialized and whether it is
        active (not closed). If these conditions are met, it asynchronously closes
        the client connection. This ensures proper release of resources and cleanup
        to prevent resource leaks.

        Returns:
            None: This method does not return a value.
        """
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()

    @classmethod
    async def register(cls, name: str, acc: str, pwd: str) -> None:
        """
        Registers a new user using the provided information asynchronously.

        This method sends a registration request to the specified endpoint with
        the provided name, account email, and password. It handles possible
        network errors or HTTP response errors from the registration process.

        Parameters:
            name: str
                The name of the user to register.
            acc: str
                The email address of the user to register.
            pwd: str
                The password for the new account.

        Raises:
            WaltIdError
                If there is a request error during registration.
            WaltIdHttpError
                If the registration request returns a status code not equal to
                201 or 409.
        """
        client = cls._get_client()

        payload = {
            "type": "email",
            "name": name,
            "email": acc,
            "password": pwd
        }

        try:
            resp = await client.post(
                url=REGISTER_ENDPOINT,
                headers={"Content-Type": "application/json"},
                json=payload
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Registration request failed: {e}") from e

        # HTTP 201: success, HTTP 409: Account already registered, equivalent to success
        if resp.status_code not in (201, 409):
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=REGISTER_ENDPOINT,
            )

    @classmethod
    async def _login(cls, email: str, password: str) -> str:
        """
        Logs in a user using email and password credentials and retrieves an authentication token.

        This asynchronous method interacts with an external login service to authenticate
        the provided credentials. On successful login, it returns a token that can be used
        for subsequent authenticated requests. If login fails due to invalid credentials
        or network issues, appropriate errors will be raised.

        Parameters:
            email (str): The email address of the user attempting to log in.
            password (str): The password associated with the provided email.

        Returns:
            str: The authentication token retrieved upon successful login.

        Raises:
            WaltIdError: If a network error occurs while making the login request.
            WaltIdHttpError: If the login request fails with status codes other than 200.
        """
        client = cls._get_client()

        payload = {
            "type": "email",
            "email": email,
            "password": password
        }

        try:
            resp = await client.post(
                url=LOGIN_ENDPOINT,
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Login request failed: {e}") from e

        # HTTP 200: success, HTTP 400/401: failure
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=LOGIN_ENDPOINT,
            )

        return resp.json().get("token")

    @classmethod
    async def _get_wallet_id(cls, token: str) -> str:
        """
        Retrieve the wallet ID associated with the provided token.

        This method sends an HTTP GET request to the WALLETID_ENDPOINT to retrieve
        the wallet ID for the account associated with the given token. The request
        requires a valid authorization token in the HTTP headers. If the request
        fails or the response indicates an error status, appropriate exceptions
        are raised.

        Parameters:
            token (str): The authorization token used to retrieve the associated
                wallet ID. Must be a valid bearer token.

        Returns:
            str: The wallet ID retrieved from the server.

        Raises:
            WaltIdError: If the request fails due to connectivity issues or a
                client-side problem.
            WaltIdHttpError: If the server response indicates an unsuccessful
                status code.
        """
        client = cls._get_client()

        try:
            resp = await client.get(
                url=WALLETID_ENDPOINT,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}"
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve wallet id: {e}") from e

        # HTTP 200: success, HTTP 401: unauthorized
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=WALLETID_ENDPOINT,
            )

        return resp.json().get("wallets")[0].get("id")

    @classmethod
    async def authenticate(cls, email: str, password: str) -> WaltIdSession:
        """
        Asynchronously retrieves a new session object by authenticating with the given
        user credentials. The session includes a token and a wallet ID, both of which
        are fetched through private methods.

        Args:
            email (str): The email address of the user.
            password (str): The password for the provided email account.

        Returns:
            WaltIdSession: A session object containing the authenticated token and
                           associated wallet ID.

        """
        # get the token and the wallet id
        token = await cls._login(email, password)
        wallet_id = await cls._get_wallet_id(token)

        return WaltIdSession(token=token, wallet_id=wallet_id)

    @classmethod
    async def get_default_did(cls, session: WaltIdSession) -> Optional[str]:
        """
        Async class method to fetch the default decentralized identifier (DID) associated with the provided wallet session.
        The method sends an HTTP GET request to retrieve the list of available DIDs for the wallet and identifies the
        default one, if present. Returns None if no default DID is found.

        Parameters:
            session (WaltIdSession): The wallet session containing the wallet ID and authorization token.

        Raises:
            WaltIdError: If there is a request-level error while communicating with the server.
            WaltIdHttpError: If the response status code is not 200, wrapping the HTTP status, response body, and endpoint URL.

        Returns:
            Optional[str]: The default DID as a string if found, otherwise None.
        """
        client = cls._get_client()
        endpoint = DEFAULT_DID_TEMPLATE.format(wallet=session.wallet_id)

        try:
            resp = await client.get(
                url=endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {session.token}"
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve default did: {e}") from e

        # HTTP 200: success, HTTP 401: unauthorized
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        # look for the first 'did' where default is True. If not found, returns None
        result = next((item.get("did") for item in resp.json() if item.get("default")), None)
        return result

    @classmethod
    async def get_credentials_list(cls, session: WaltIdSession) -> list:
        """
        Retrieves a list of credentials associated with a given WaltId session.

        This method communicates with a WaltId-compatible API to fetch a list of
        stored credentials. It requires a valid `WaltIdSession` object that contains
        the session's wallet ID and authorization token. Communication is handled
        asynchronously using the `httpx` library.

        Raises WaltIdError in case of network errors during the request process.
        Raises WaltIdHttpError if the server returns a non-200 HTTP status code.

        Parameters:
            session (WaltIdSession): The session containing wallet ID and
                authorization token for authenticating the request.

        Returns:
            list: A list of credentials retrieved from the API.

        Raises:
            WaltIdError: If there is a network error while attempting to retrieve
                the credentials.
            WaltIdHttpError: If the API returns a non-200 HTTP status code.
        """
        client = cls._get_client()
        endpoint = CREDENTIALS_TEMPLATE.format(wallet=session.wallet_id)

        try:
            resp = await client.get(
                url=endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {session.token}"
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve credentials list: {e}") from e

        # HTTP 200: success, HTTP 401: failure
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        return resp.json()

    @classmethod
    async def _get_key_id(cls, session: WaltIdSession) -> str:
        """
        Retrieve the key ID for the session asynchronously.

        This method sends a GET request to the wallet's key retrieval endpoint using
        the session's wallet ID and authorization token. The key selection logic
        defaults to the first key ID in the response. Future updates may involve
        enhanced selection mechanisms. Raises an exception in case of request
        failures or non-200 HTTP responses.

        Args:
            session (WaltIdSession): The session object containing wallet ID and token.

        Returns:
            str: The retrieved key ID.

        Raises:
            WaltIdError: If the request fails during execution.
            WaltIdHttpError: If the response status code is not 200.
        """
        client = cls._get_client()
        endpoint = KEYS_ENDPOINT_TEMPLATE.format(wallet=session.wallet_id)

        try:
            resp = await client.get(
                url=endpoint,
                headers={
                    "Authorization": f"Bearer {session.token}",
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve key(s) id: {e}") from e

        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        # NOTE
        # Defaulting to the first keyId. Future implementations might require specific key selection logic.
        key_id = resp.json()[0]["keyId"]["id"]
        return key_id

    @classmethod
    async def export_key_jwk(cls, session: WaltIdSession, key_id: Optional[str] = None,
                             load_private: bool = True) -> dict:
        """
        Exports a key in JWK format from the wallet associated with the provided session.

        This method exports a cryptographic key from the WaltId wallet in JSON Web Key (JWK)
        format. If no specific key ID is provided, the method defaults to exporting the first
        key available in the wallet. The exported key can include the private key portion
        if the `load_private` parameter is set to `True`.

        Arguments:
            session (WaltIdSession): An instance of WaltIdSession providing the wallet
                information and authentication token for accessing the WaltId service.
            key_id (Optional[str]): The unique identifier of the key to export. If not
                provided, the method will default to the first available key in the
                wallet.
            load_private (bool): A flag indicating whether to include the private key
                in the exported JWK. Set to `True` to include, or `False` to exclude
                the private key. Defaults to `True`.

        Returns:
            dict: A dictionary containing the key in JWK format.

        Raises:
            WaltIdError: If there is an error specific to the WaltId operation, such as
                retrieving the `key_id` or initiating the client request.
            WaltIdHttpError: If the HTTP request to the WaltId service fails with a
                status code other than 200.
        """
        # NOTE
        # Defaulting to the first keyId. Future implementations might require specific key selection logic.
        if key_id is None:
            key_id = await cls._get_key_id(session=session)

        # docs show /wallet/{wallet}/keys/export/{keyId}?format=JWK&loadPrivateKey=true
        params = {
            "format": "JWK",
            "loadPrivateKey": "true" if load_private else "false",
        }
        client = cls._get_client()

        endpoint = KEY_EXPORT_TEMPLATE.format(wallet=session.wallet_id, key=key_id)

        try:
            resp = await client.get(
                url=endpoint,
                params=params,
                headers={
                    "Authorization": f"Bearer {session.token}",
                    "accept": "*/*"
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to export the key with kid: {key_id}: {e}") from e

        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        return resp.json()

    @classmethod
    async def match_creds_for_pres_def(cls, session: WaltIdSession, presentation_definition: dict) -> dict:
        """
        This method is an asynchronous class-level method that retrieves credentials matching a
        given presentation definition for a specific WaltId session. It communicates with an external
        service using an HTTP POST request. If the request is successful, the method returns the
        first credential that matches the criteria. In the case of errors, specific exceptions are raised
        to handle request or HTTP response issues.

        Parameters:
            session (WaltIdSession): The session object containing wallet and authentication token
                required for the request.
            presentation_definition (dict): The presentation definition for matching credentials.

        Returns:
            dict: The first credential matching the provided presentation definition.

        Raises:
            WaltIdError: If a request error occurs while attempting to retrieve matching credentials.
            WaltIdHttpError: If the HTTP response status code is not 200, indicating an unsuccessful
                request.
        """
        client = cls._get_client()
        endpoint = MATCH_CREDS_TEMPLATE.format(wallet=session.wallet_id)

        try:
            resp = await client.post(
                url=endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {session.token}"
                },
                json=presentation_definition
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve credential(s) that match(es) list: {e}") from e

        # HTTP 200: success, HTTP 401: unauthenticated
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        # NOTE
        # Defaulting to the first credential that matches
        return resp.json()[0]

    @classmethod
    async def get_credential_by_id(cls, session: WaltIdSession, credential_id: str) -> dict:
        """
        Asynchronously retrieves a specific credential by its unique identifier.

        This method interacts with an external service through an HTTP GET request to
        retrieve the credential associated with the given `credential_id`.
        The method requires a valid session containing authentication details and
        ensures proper error handling for failed requests due to network issues
        or invalid authentication.

        Parameters:
            session (WaltIdSession): The session object containing wallet and
                authentication token details.
            credential_id (str): Unique identifier of the credential to be retrieved.

        Returns:
            dict: A dictionary representation of the retrieved credential.

        Raises:
            WaltIdError: If a network-related error occurs during the request.
            WaltIdHttpError: If the HTTP response status code is not 200 (e.g.,
                authentication failure or resource not found).
        """
        client = cls._get_client()
        endpoint = CRED_ID_TEMPLATE.format(wallet=session.wallet_id, credential_id=credential_id)

        try:
            resp = await client.get(
                url=endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {session.token}"
                },
            )
        except httpx.RequestError as e:
            raise WaltIdError(f"Failed to retrieve credential with id {credential_id}: {e}") from e

        # HTTP 200: success, HTTP 401: unauthenticated
        if resp.status_code != 200:
            raise WaltIdHttpError(
                status_code=resp.status_code,
                body=resp.text,
                endpoint=endpoint,
            )

        return resp.json()
