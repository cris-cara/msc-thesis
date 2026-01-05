import httpx
from common import get_logger
from a2a.client import A2ACardResolver
from a2a.types import AgentCard

logger = get_logger(__name__)

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
