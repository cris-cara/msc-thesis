import asyncio
from dataclasses import asdict
from typing import Optional

import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore

import bob.helpers as helpers
from bob.helpers import AzureOpenAIClient, ProtectExtendedCardMiddleware
from bob.executors.didcomm_executor import DIDCommExecutor
from bob.mcp.hub import McpHub
from bob.routes import build_router
from common import config, get_logger
from common import rehydrate_after_mcp_tool_call
from common.agents import Agent
from common.waltid_core import WaltIdSession
from bob.executors.a2a_didauth_executor import A2ADidAuthExecutor
from bob.executors.router_agent_executor import RouterAgentExecutor

# =================== CONFIG ===================
cfg = config()

BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BOB_DID = cfg["DIDs"]["bob"]
EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
GREEN = cfg["colors"]["GREEN"]
RESET = cfg["colors"]["RESET"]

logger = get_logger(__name__)  # get a logger instance
# ==============================================

class Bob(Agent):
    """
    Represents an agent named Bob designed to use MCP hub functionality for connecting
    to servers and authenticating with third-party services like WaltID. This class
    utilizes Azure OpenAI client and sets up tools while interacting with multiple servers.

    The primary purpose of this class is to simplify the integration of different
    MCP servers and provide seamless authentication mechanisms for WaltID, along
    with handling related session and DID management.

    Attributes:
        mcp_hub (McpHub): Represents an instance of the"""
    def __init__(self):
        super().__init__(env_file_path="bob/bob.env")
        self.mcp_hub: McpHub = McpHub()
        self.llm: AzureOpenAIClient = helpers.create_azure_openai_client()

    async def mcp_connect(self, command: str, args: Optional[list[str]] = None) -> None:
        """
        Connects to multiple MCP servers and refreshes tools.

        This method establishes connections to predefined MCP servers, specifically
        a weather server and a walt.id server, using the provided command and additional
        arguments if applicable. After establishing connections, it refreshes the MCP
        tools to ensure the servers are properly integrated.

        Parameters:
            command: str
                The command to execute the server connection.
            args: Optional[list[str]], optional
                Additional arguments for the server connection command. Defaults to None.
        """
        logger.info(f"[{self.__class__.__name__}] Connecting to MCP hub...")

        # 1) WEATHER MCP server (3rd party)
        weather_init = await self.mcp_hub.add_stdio_server(
            server_key="weather",
            command=command,
            args=["run", "mcp_weather_server"],
        )
        logger.info(f"{GREEN}[{self.__class__.__name__}] Connected to MPC server: {weather_init.serverInfo}{RESET}")

        # 2) WALT.ID MCP server (custom)
        waltid_init = await self.mcp_hub.add_stdio_server(
            server_key="waltid",
            command=command,
            args=["run", "-m", "bob.mcp.waltid_server"],
        )
        logger.info(f"{GREEN}[{self.__class__.__name__}] Connected to MPC server: {waltid_init.serverInfo}{RESET}")

        # refresh the MCP tools
        await self.mcp_hub.refresh_tools()

    async def sign_in(self) -> None:
        """
        Signs in the user to WaltID via the MCP (Multi-Channel Processing) hub.

        This asynchronous method performs the authentication and initializes necessary session
        data for interacting with the WaltID platform. It also retrieves and sets the default
        Decentralized Identifier (DID) for the user.

        Raises:
            RuntimeError: If the MCP hub is not initialized before calling this method.
            ValueError: If the DID could not be retrieved after a successful login.
        """
        if not self.mcp_hub:
            raise RuntimeError("MCP hub not initialized. Call mcp_connect() first.")

        logger.info(f"[{self.__class__.__name__}] Logging in to WaltID via MCP...")
        result = await self.mcp_hub.call(
            tool_alias="waltid.authenticate",
            arguments={"email": self.email, "password": self.password}
        )

        # set the waltid_session attribute
        self.waltid_session = rehydrate_after_mcp_tool_call(
            tool_result=result,
            target_class=WaltIdSession
        )

        # set the default DID
        did_result = await self.mcp_hub.call(
            tool_alias="waltid.get_default_did",
            arguments={"session": asdict(self.waltid_session)}
        )

        if did_result.content and hasattr(did_result.content[0], 'text'):
            self.did = rehydrate_after_mcp_tool_call(tool_result=did_result, target_class=str)
        else:
            raise ValueError("Impossible to retrieve DID from WaltID")

        logger.info(f"{GREEN}[{self.__class__.__name__}] Login successful. DID: {self.did}{RESET}")

async def main():
    # initialize Bob
    bob = Bob()

    try:
        # connect to the MCP hub
        await bob.mcp_connect(command="uv")

        # authenticate to waltId wallet
        await bob.sign_in()
        # set the resolvers_config for DIDComm library
        bob.set_resolvers_config()

        # build DIDComm agent executor
        didcomm_executor = DIDCommExecutor(
            did=bob.did,
            llm_client=bob.llm["client"],
            mcp_hub=bob.mcp_hub,
            azure_deployment=bob.llm["deployment_name"],
            llm_tools_allowlist={"weather"},  # <-- LLM sees only weather.* tools (not waltid.* ones)
            resolvers_cfg=bob.resolvers_config,
        )

        # build A2A DIDAuth executor
        a2a_didauth_executor = A2ADidAuthExecutor(
            did=bob.did,
            mcp_hub=bob.mcp_hub,
            waltid_session=bob.waltid_session,
            ext_uri=EXT_URI,  # a2a-didauth extensions URI
        )

        # build Router agent executor
        router_executor = RouterAgentExecutor(
            didcomm_executor=didcomm_executor,
            a2a_didauth_executor=a2a_didauth_executor,
            ext_uri=EXT_URI,
        )

        # create Bob agent card (both public and extended)
        public_agent_card = helpers.create_agent_card(BOB_BASE_URL,did=BOB_DID, authenticated=False)
        extended_agent_card = helpers.create_agent_card(BOB_BASE_URL, did=BOB_DID, authenticated=True)  # skills=[weather_didcomm]

        # initialize A2A server
        request_handler = DefaultRequestHandler(
            agent_executor=router_executor,
            task_store=InMemoryTaskStore(),
        )
        server_app = A2AStarletteApplication(
            http_handler=request_handler,
            agent_card=public_agent_card,
            extended_agent_card=extended_agent_card,
        )
        app = server_app.build()

        # add middleware to protect the extended card JSON-RPC endpoint
        app.add_middleware(
            ProtectExtendedCardMiddleware,
            rpc_paths={"/rpc", "/"},  # <-- here the real path that receives JSON-RPC
            protected_methods={"agent/getAuthenticatedExtendedCard"},
        )

        # attach routes from bob/routes/router.py
        # {'POST'} / getPresentationRequest
        # {'POST'} / getAccessToken
        router = build_router(resolver_config=bob.resolvers_config)
        app.router.routes.extend(router.routes)

        server_cfg = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=8443,
            log_level="info",
            # HTTPS: Use a self-signed test certificate. Generate the certificate files using:
            # openssl req -x509 -newkey rsa:4096 -keyout certs/bob-key.pem -out certs/bob-cert.pem -days 365 -nodes -subj "/CN=localhost"
            ssl_keyfile="bob/certs/bob-key.pem",
            ssl_certfile="bob/certs/bob-cert.pem",
        )

        server = uvicorn.Server(server_cfg)
        await server.serve()

    except Exception as e:
        raise SystemExit(f"Error: {e}")
    finally:
        # cleanup and safe exit
        await bob.cleanup()
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
