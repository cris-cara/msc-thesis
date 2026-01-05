import os
import requests
from typing import Union
from common import config
from dotenv import load_dotenv

# =================== CONFIG ===================
load_dotenv(".env", override=True)
cfg = config()

BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
TENANT_ID = cfg["MSEntraID"]["az_tenant_id"]
CLIENT_ID = cfg["MSEntraID"]["az_client_id"]
OAUTH_SCOPE = cfg["MSEntraID"]["az_oauth_scope"]
ISSUER_API_URL = cfg["MSEntraID"]["issuer_api_url"]
VERIFIER_API_URL = cfg["MSEntraID"]["verifier_api_url"]
DID_AUTHORITY = cfg["MSEntraID"]["did_authority"]
MANIFEST = cfg["MSEntraID"]["manifest"]
CALLBACK_URL = cfg["MSEntraID"]["callback_url"]

OAUTH_SECRET = os.getenv("OAUTH_SECRET", "<client-secret>")
CALLBACK_API_KEY = os.getenv("CALLBACK_API_KEY", "<api-key>")
# ==============================================

def _get_oauth_token(tenant_id: str, client_id: str, oauth_secret: str, scope: str) -> str:
    """
    Fetches the OAuth token for authenticating with Microsoft services.

    This function retrieves an OAuth access token using the given tenant ID, client ID,
    OAuth secret, and scope. The token is required for authenticating API requests to
    Microsoft services.

    Parameters:
        tenant_id (str): The tenant ID of the Microsoft Azure application.
        client_id (str): The client ID of the Microsoft Azure application.
        oauth_secret (str): The client secret or OAuth secret for the application.
        scope (str): The scope for which the OAuth access token is requested.

    Returns:
        str: The access token retrieved from the authentication service.

    Raises:
        SystemExit: If an HTTP error occurs during the request, or if the response does not
        contain an access token.
    """
    data = {
        "client_id": client_id,
        "client_secret": oauth_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    }

    resp = requests.post(
        url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
        timeout=20
    )

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        raise SystemExit(f"[TOKEN ERROR] {resp.status_code} {resp.text}")
    token = resp.json().get("access_token")

    if not token:
        raise SystemExit("[TOKEN ERROR] access_token missing in the response!")
    return token

def create_presentation_request(state: str) -> dict[str, Union[str, int]]:
    """
    Creates a verifiable credential presentation request for a specified state.

    This function generates a payload containing information about the issuing authority,
    callback configuration, and requested credentials. It authenticates with an OAuth token
    before making a POST request to the verifier API to initiate the presentation process.

    Parameters:
    state (str): A unique identifier or state string that applies to the callback URL
                 for tracking the request progress.

    Returns:
    dict[str, Union[str, int]]: A dictionary containing the JSON response from the
                                verifier API endpoint, including details of the
                                presentation request.
    """
    oauth_token_ms = _get_oauth_token(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        oauth_secret=OAUTH_SECRET,
        scope=OAUTH_SCOPE
    )

    if not CALLBACK_URL:
        raise RuntimeError("Missing callback_url (set env CALLBACK_URL)")
    if not CALLBACK_API_KEY:
        raise RuntimeError("Missing/invalid CALLBACK_API_KEY (set env CALLBACK_API_KEY)")

    payload = {
        "authority": DID_AUTHORITY,
        "callback": {
            "url": CALLBACK_URL,
            "state": state,
            "headers": {
              "api-key": CALLBACK_API_KEY
            }
        },
        "registration": {
            "clientName": "Veritable Credential Expert Verifier"
        },
        "includeReceipt": False,
        "requestedCredentials": [
            {
                "type": "VerifiedCredentialExpert",
                "purpose": "So we can see that you a veritable credentials expert",
                "acceptedIssuers": [DID_AUTHORITY],
                "configuration": {
                    "validation": {
                        "allowRevoked": True,
                        "validateLinkedDomain": True
                    }
                }
            }
        ]
    }

    presentation_request = requests.post(
        url=VERIFIER_API_URL,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {oauth_token_ms}"
        },
        json=payload,
        timeout=15
    )

    # return the entire presentation request object
    return presentation_request.json()
