import logging
from typing import Optional, Any

import httpx
from a2a.client import A2ACardResolver
from a2a.types import AgentCard

logger = logging.getLogger(__name__)

def get_extension_uri(card: AgentCard) -> str:
    """
    Retrieves the DID authentication profile URI from the provided AgentCard.

    Inspects the extensions in the AgentCard object's capabilities to find the
    URI related to "a2a-didauth". If no such URI exists, it raises a RuntimeError.

    Args:
        card (AgentCard): The AgentCard object containing possible extensions
            from which the DID authentication profile URI will be extracted.

    Returns:
        str: The URI string corresponding to the "a2a-didauth" profile.

    Raises:
        RuntimeError: If no extension with an "a2a-didauth" URI is found.
    """
    exts = (card.capabilities.extensions or []) if card.capabilities else []
    for e in exts:
        if e.uri and "a2a-didauth" in e.uri:
            return e.uri

    raise RuntimeError("Bob AgentCard has no extensions to activate.")

def get_did_from_params(card: AgentCard, ext_uri: str) -> Optional[dict[str, Any]]:
    """
    Extracts the DID (Decentralized Identifier) from the parameters of a specified
    extension URI in an AgentCard. The method searches through a list of extensions
    within the AgentCard to locate the extension with the given URI, retrieves its
    parameters, and returns the "dids" value from these parameters if it exists.

    Args:
        card (AgentCard): The AgentCard containing a list of extensions that define
            capabilities and metadata.
        ext_uri (str): The URI of the extension whose parameters are to be searched
            for the "dids" key.

    Returns:
        Optional[dict[str, Any]]: The "dids" value retrieved from the parameters of
        the specified extension. Returns None if "dids" is not found within the
        parameters.

    Raises:
        RuntimeError: If the extension with the specified URI is not found in the
        AgentCard or it does not contain any parameters.
    """
    exts = (card.capabilities.extensions or []) if card.capabilities else []
    ext = next((e for e in exts if e.uri == ext_uri), None)

    params = ext.params if ext else None
    if not params:
        raise RuntimeError(f"Extension {ext_uri} not found in AgentCard")

    return params.get("dids")

async def discover_agent_card(url: str) -> AgentCard:
    """
    Fetches the public agent card for Bob's agent asynchronously.

    This function establishes an asynchronous HTTP connection, attempts to fetch
    the public agent card from Bob's agent, and logs the process. The function wraps
    critical errors and raises a runtime exception if the public agent card cannot
    be retrieved.

    Returns:
        AgentCard: The public agent card of Bob's agent fetched from the specified
        endpoint.

    Raises:
        RuntimeError: Raised if an error occurs while attempting to fetch the public
        agent card and prevents further operations.
    """
    async with httpx.AsyncClient(verify="bob/certs/bob-cert.pem") as client:
        resolver = A2ACardResolver(
            httpx_client=client,
            base_url=url,
        )
        try:
            logger.info(f'Attempting to fetch public agent card from: {url}/.well-known/agent-card.json')
            _public_card = await resolver.get_agent_card()

            logger.info('Successfully fetched public agent card')
            # decomment if you want to print the public card
            # logger.info(_public_card.model_dump_json(indent=2, exclude_none=True))

        except Exception as e:
            logger.error(f'Critical error fetching public agent card: {e}', exc_info=True)
            raise RuntimeError('Failed to fetch the public agent card. Cannot continue.') from e

        return _public_card
