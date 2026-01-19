import os
from abc import abstractmethod, ABC
from contextlib import AsyncExitStack
from typing import Optional
from dotenv import load_dotenv

from didcomm.common.resolvers import ResolversConfig
from common import config, get_logger
from common.didcomm_interfaces import SecretsResolver4JWK, StaticDIDResolver
from common.waltid_core import WaltIdSession
from common.waltid_core import WaltIdClient as waltid


# =================== CONFIG ===================
cfg = config()

RED = cfg["colors"]["RED"]
RESET = cfg["colors"]["RESET"]

logger = get_logger(__name__)  # Get a logger instance
# ==============================================

class Agent(ABC):
    def __init__(self, env_file_path: str):
        # load specific .env file
        load_dotenv(env_file_path, override=True)

        self.email: str = os.getenv("EMAIL", "<email>")
        self.password: str = os.getenv("PASSWORD", "<password>")

        self.did: Optional[str] = None
        self.waltid_session: Optional[WaltIdSession] = None

        self.resolvers_config: Optional[ResolversConfig] = None

        # MCP server/hub exit stack
        self._exit_stack = AsyncExitStack()

    async def cleanup(self) -> None:
        """Closes all resources registered in the stack."""
        logger.info(f"{RED}[{self.__class__.__name__}] Cleaning up resources...{RESET}")
        await self._exit_stack.aclose()

    def set_resolvers_config(self) -> None:
        """
        Configures the resolvers for DIDs and secrets in the application.

        Summary:
        This method initializes and configures the resolvers used for handling
        DIDs (Decentralized Identifiers) and secrets. It sets up a static DID
        resolver and a secrets resolver configured for JSON Web Key (JWK)
        management, enabling efficient and secure DID resolution and key
        management.

        Raises:
            No explicit exceptions are raised by this method, but errors may
            occur if required configurations or dependencies for the resolvers
            are not properly set up.

        Attributes:
            resolvers_config (ResolversConfig): An instance that holds the
            configuration for both the secrets resolver and did resolver.
        """
        # initialize DIDs resolver
        did_resolver = StaticDIDResolver()

        # initialize secrets resolver
        secrets_resolver = SecretsResolver4JWK(
            waltid=waltid,
            session=self.waltid_session,
            cache=True
        )

        self.resolvers_config = ResolversConfig(
            secrets_resolver=secrets_resolver,
            did_resolver=did_resolver,
        )

    @abstractmethod
    async def mcp_connect(self, command: str, args: Optional[list[str]] = None) -> None:
        """Abstract asynchronous method that establishes a connection to an MCP-compatible service"""
        pass

    @abstractmethod
    async def sign_in(self) -> None:
        """Abstract method that handles the process of signing in to waltid wallet"""
        pass
