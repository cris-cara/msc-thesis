import json
import ssl
import sys
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import httpx
import pytest
import pytest_asyncio
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from mcp import ClientSession, StdioServerParameters, stdio_client

from common import get_logger
from common import rehydrate_after_mcp_tool_call
from common.agents import Agent
from common.config import config
from common.waltid_core import WaltIdSession

# =================== CONFIG ===================
BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"

cfg = config()
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BOB_DID = cfg["DIDs"]["bob"]
EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
GREEN = cfg["colors"]["GREEN"]
RESET = cfg["colors"]["RESET"]

logger = get_logger(__name__)  # Get a logger instance
# ==============================================

class MitmAgent(Agent):
    def __init__(self):
        super().__init__(env_file_path="test/mitm.env")
        self.mcp_session: ClientSession | None = None

    async def mcp_connect(self, command: str, args: Optional[list[str]] = None) -> None:
        """
        Establishes a connection to an MCP server using provided command and arguments.

        This asynchronous method attempts to create a connection to an MCP server using
        a standard input-output (stdio) communication protocol. It initializes the server
        interaction session, configures the communication protocol, and completes the handshake
        process by invoking the session's initialization method.

        Parameters:
        command: str
            The command to be executed for initiating the MCP server process.

        args: list[str]
            A list of arguments accompanying the command for the MCP server process.

        Returns:
        None
        """
        logger.info(f"[{self.__class__.__name__}] Connecting to MCP server...")

        server_params = StdioServerParameters(
            command=command,
            args=args,
        )

        # start server process (stdio)
        read, write = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )

        # set mcp_session
        self.mcp_session = await self._exit_stack.enter_async_context(
            ClientSession(read, write)
        )

        # initialize protocol
        init_result = await self.mcp_session.initialize()
        logger.info(f"{GREEN}[{self.__class__.__name__}] Connected to MCP server: {init_result.serverInfo}{RESET}")

    async def sign_in(self) -> None:
        """
        Logs the user into WaltID via an MCP session and retrieves the default DID.

        Raises
        ------
        RuntimeError
            If the MCP session is not initialized.

        ValueError
            If the DID cannot be retrieved from WaltID.

        Notes
        -----
        This method performs authentication using the `authenticate` tool provided
        by the MCP session. On successful authentication, it updates the
        `waltid_session` attribute with the session data returned from authentication.
        After the session is established, it retrieves and assigns the default DID
        to the `did` attribute by calling the `get_default_did` tool from the MCP session.
        """
        if not self.mcp_session:
            raise RuntimeError("MCP Session not initialized. Call mcp_connect() first.")

        logger.info(f"[{self.__class__.__name__}] Logging in to WaltID via MCP...")
        result = await self.mcp_session.call_tool(
            name="authenticate",
            arguments={"email": self.email, "password": self.password}
        )

        # set the waltid_session attribute
        self.waltid_session = rehydrate_after_mcp_tool_call(
            tool_result=result,
            target_class=WaltIdSession
        )

        # set the default DID
        did_result = await self.mcp_session.call_tool(
            name="get_default_did",
            arguments={"session": asdict(self.waltid_session)}
        )

        if did_result.content and hasattr(did_result.content[0], 'text'):
            self.did = rehydrate_after_mcp_tool_call(tool_result=did_result, target_class=str)
        else:
            raise ValueError("Impossible to retrieve DID from WaltID")

        logger.info(f"{GREEN}[{self.__class__.__name__}] Login successful. DID: {self.did}{RESET}")

@pytest_asyncio.fixture
async def agent_mitm():
    """ Initialize the hardcoded Man in the Middle (MITM) agent."""
    agent_mitm = MitmAgent()

    await agent_mitm.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await agent_mitm.sign_in()
    agent_mitm.set_resolvers_config()

    yield agent_mitm

@pytest_asyncio.fixture
async def bob_https():
    """ Initialize Bob's HTTP client."""
    client = httpx.AsyncClient(
        base_url=BOB_BASE_URL,
        verify=ssl.create_default_context(cafile="project/bob/certs/bob-cert.pem"),
        timeout=httpx.Timeout(10.0),
    )
    client.headers.update(
        {
            "A2A-Extensions": EXT_URI,
            "X-A2A-Extensions": EXT_URI,
            "A2A-Version": "0.3",
        }
    )

    yield client
    await client.aclose()

@pytest.mark.asyncio
async def test_vp_token_replay_attack(agent_mitm, bob_https: httpx.AsyncClient):
    #* assume that the MITM stole a valid Microsoft Entra request_id and an entry of
    #* 'bob/didauth_sessions.json'
    didauth_session_trace = {
        "af74839a-016f-47cd-91e8-c238ca183989": {
            "client_did": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2Iiwia2lkIjoiZDQ5UFAzQ2oycnQwX0Rha2stN3VvQzFpS1I5QXNrQkpIN1lrTFFXRW9vUSIsIngiOiJFQzZIRzhOWlZLSy1EaVVQY3NkWktnUGxxbUpFMVVHZmJsbkRwSHBjcTZrIiwieSI6IjBfV1lrN2ljMk12ekd1WWJtOWJBcjM0Vkxkb2F4VndscVZUTjVIMmhlRmMifQ",
            "context_id": "3814764b-be43-43cd-8788-2353db249233",
            "expires_at": 1773842317,
            "nonce": "fdea181e-cbbd-49e6-a6dd-56b03b1ff852",
            "status": "used",
            "task_id": "af74839a-016f-47cd-91e8-c238ca183989"
        }
    }
    key_trace = "af74839a-016f-47cd-91e8-c238ca183989"

    body = {
        "did_subject": didauth_session_trace.get(key_trace).get("client_did"),
        "MS_request_id": "a0e8de3f-5b01-466c-906c-eb180f46b950", #! valid hardcoded request_id (stolen)
        "didauth_task_id": didauth_session_trace.get(key_trace).get("task_id"),
        "didauth_nonce": didauth_session_trace.get(key_trace).get("nonce"),
    }

    #* packing DIDComm message
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/vp-token-request",
        body=body,
        frm=agent_mitm.did,
        to=[BOB_DID],
    )

    jwe_request_json = await pack_encrypted(
        resolvers_config=agent_mitm.resolvers_config,
        message=didcomm_msg,
        frm=agent_mitm.did,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    #* send the payload to Bob
    resp = await bob_https.post(
        url="/getAccessToken",
        json=json.loads(jwe_request_json.packed_msg),
    )

    # ! see bob/routes/router.py (_get_access_token)
    assert resp.status_code == 403
    assert resp.json() == {"error":"Sender DID mismatch"}