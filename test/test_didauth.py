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

# =================== CONFIG ===================
BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"
IMPERSONATION_DID = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2Iiwia2lkIjoiUkx2eTIyTDZLcG5SNnd5T1BOelktNUdPcHVwS3hhQzdpRGdXcE4xSk9UQSIsIngiOiJ3TGI1OFdBZGhGalhmXzBUMUJLNmRzVGZ3VWRFODhUdmJwV2U1VFo1c0VVIiwieSI6IndUN01nWW16UGJHaFBpTzFEaklZTk9LdS1DYUoxY2U4d2pweTJfQmhPV1EifQ"

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

@pytest.mark.asyncio
async def test_impersonation(alice: Agent, bob_https: httpx.AsyncClient):
    A2ADidAuthService.set_ext_uri(ext_uri=EXT_URI)
    A2ADidAuthService.set_client(client=bob_https)

    #* - A2ADIDAuth: PHASE 1
    nonce = str(uuid.uuid4())
    resp = await A2ADidAuthService.send_did_auth_request(
        client_did=alice.did,
        nonce=nonce
    )

    #* - A2ADIDAuth: PHASE 3 and 4
    # retrieve the private key from waltid wallet
    result = await alice.mcp_session.call_tool(
        name="export_key_jwk",
        arguments={"session": alice.waltid_session, "load_private": True}
    )
    private_key = rehydrate_after_mcp_tool_call(result, dict)

    with pytest.raises(A2ADidAuthError) as exif:
        await A2ADidAuthService.send_did_auth_response(
            a2a_resp=resp,
            client_did=IMPERSONATION_DID, #! IMP. change DID to simulate impersonation attack
            nonce=nonce,
            signing_key_jwk=private_key,
        )

    msg = str(exif.value)
    assert "Error while verifying challenge JWS:" in msg
    assert "Mismatch between DID in header and aud in payload" in msg
