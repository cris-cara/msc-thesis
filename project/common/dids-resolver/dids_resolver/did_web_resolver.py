from __future__ import annotations

from typing import Any
import httpx, json

def _normalize_url(did: str) -> str:
    """
    Normalizes a DID (Decentralized Identifier) of type `did:web` into its corresponding
    URL representation. This function converts DIDs that start with `did:web:` into
    a standard HTTPS URL, conforming to the .well-known DID JSON location.

    :param did: The Decentralized Identifier (DID) to be normalized. Must be a string
        starting with 'did:web'.
    :return: A string representing the normalized URL for the given DID.
    :rtype: str
    :raises ValueError: If the given DID does not start with 'did:web'.
    """
    # expected did:web:... (e.g. did:web:stgacctestdid.z38.web.core.windows.net)
    if not did.startswith('did:web'):
        raise ValueError('did must be did:web')

    # craft the url (e.g. https://stgacctestdid.z38.web.core.windows.net/.well-known/did.json)
    url = did.replace('did:web:', 'https://') + '/.well-known/did.json'
    return url

def resolve_did_web(did: str, mode: str = "dict") -> dict[str, Any] | str:
    """
    Resolves a Decentralized Identifier (DID) document using a specified mode.

    This function fetches the DID document from the normalized DID URL via an HTTP
    GET request. The returned document can either be in JSON string format or
    a Python dictionary, depending on the mode provided.

    :param did: The Decentralized Identifier to resolve.
    :type did: str
    :param mode: The mode in which to return the DID document. Acceptable values
        are "dict" (default) for a Python dictionary and "json" for a JSON string.
    :type mode: str
    :return: The resolved DID document. A Python dictionary is returned if
        the mode is "dict", while a JSON string is returned if the mode is "json".
    :rtype: dict[str, Any] | str
    :raises Exception: If the mode provided is not "json" or "dict".
    :raises SystemExit: If the HTTP request to retrieve the DID document fails.
    """
    url = _normalize_url(did)

    if mode not in ["json", "dict"]:
        raise Exception ('mode must be json or dict')

    try:
        resp = httpx.get(url, timeout=20.0)
        resp.raise_for_status()
    except httpx.HTTPStatusError:
        raise SystemExit(
            f"Impossible to retrieve DID document of {did}! {resp.status_code} {resp.text}"
        )
    except httpx.RequestError as e:
        # network errors / timeout / DNS etc.
        raise SystemExit(f"Request failed for {did}: {e}")

    if mode == "json":
        # use dumps if a raw JSON string is needed (e.g., for printing)
        did_document = json.dumps(resp.json(), indent=2)
    else:
        # use resp.json to get a Python object (e.g., to access fields like id)
        did_document = resp.json()

    return did_document