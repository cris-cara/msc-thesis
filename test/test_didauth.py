#* Imagine that there's a MITM Eve that begins the A2ADIDAuth interaction using its DID and key material, but then
#* in the JWS challenge response she uses Alice's DID to try an impersonation attack in the last phase

import ssl
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from a2a_didauth.core.errors import A2ADidAuthError
from a2a_didauth.core.service import A2ADidAuthService
from alice.__main__ import Alice
from common import rehydrate_after_mcp_tool_call
from common.agents import Agent
from common.config import config
from eve.__main__ import Eve

# =================== CONFIG ===================
BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"

cfg = config()
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
# ==============================================

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

@pytest_asyncio.fixture
async def alice():
    """ Initialize Alice agent."""
    alice = Alice()
    await alice.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await alice.sign_in()
    alice.set_resolvers_config()

    yield alice

@pytest_asyncio.fixture
async def eve():
    """ Initialize Eve agent."""
    eve = Eve()
    await eve.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await eve.sign_in()
    eve.set_resolvers_config()

    yield eve

@pytest.mark.asyncio
async def test_impersonation(alice: Agent, eve: Agent, bob_https: httpx.AsyncClient):
    A2ADidAuthService.set_ext_uri(ext_uri=EXT_URI)
    A2ADidAuthService.set_client(client=bob_https)

    #* - A2ADIDAuth: PHASE 1
    nonce = str(uuid.uuid4())
    resp = await A2ADidAuthService.send_did_auth_request(
        client_did=eve.did,
        nonce=nonce
    )

    #* - A2ADIDAuth: PHASE 3 and 4
    # retrieve the private key from waltid wallet
    result = await eve.mcp_session.call_tool(
        name="export_key_jwk",
        arguments={"session": eve.waltid_session, "load_private": True}
    )
    private_key = rehydrate_after_mcp_tool_call(result, dict)

    with pytest.raises(A2ADidAuthError) as exif:
        await A2ADidAuthService.send_did_auth_response(
            a2a_resp=resp,
            client_did=alice.did, #! IMP. change DID (insert Alice DID) to simulate an impersonation attack
            nonce=nonce,
            signing_key_jwk=private_key,
        )

    msg = str(exif.value)
    assert "Error while verifying challenge JWS:" in msg
    assert "Mismatch between DID in header and aud in payload" in msg
