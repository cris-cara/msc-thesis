import ssl
import sys
from pathlib import Path
import uuid
import httpx
import pytest
from a2a_didauth.core.service import A2ADidAuthService
from alice.__main__ import Alice
from common.agents import Agent
from common.config import config
from common import rehydrate_after_mcp_tool_call

BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"

# =================== CONFIG ===================
cfg = config()

BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
# ==============================================

async def _initialize(agent: Agent):
    # initialize reusable httpx client
    bob_https = httpx.AsyncClient(
        base_url=BOB_BASE_URL,
        verify=ssl.create_default_context(cafile="project/bob/certs/bob-cert.pem"),
        timeout=httpx.Timeout(10.0),
    )

    # connect to the MCP waltid server
    await agent.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )

    # authenticate to waltId wallet
    await agent.sign_in()
    # set the resolvers_config for DIDComm library
    agent.set_resolvers_config()

    # update and set the BOB client HTTPS
    bob_https.headers.update(
        {
            "A2A-Extensions": EXT_URI,  # activates the extension for this request
            "X-A2A-Extensions": EXT_URI,  # ! IMP for backward compatibility
            "A2A-Version": "0.3",  # optional but consistent with the spec examples
        }
    )

    return bob_https

@pytest.mark.asyncio
async def test_impersonation():
    alice = Alice()

    bob_https = await _initialize(alice)

    A2ADidAuthService.set_ext_uri(ext_uri=EXT_URI)
    A2ADidAuthService.set_client(client=bob_https)

#* - A2ADIDAuth: PHASE 1
    try:
        #! IMP. choose a random nonce and memorize it also for later (/getAccessToken)
        nonce = str(uuid.uuid4())

        resp = await A2ADidAuthService.send_did_auth_request(
            client_did=alice.did,
            nonce=nonce
        )

        # retrieve taskId and contextId from the response
        task_id = resp['result']['id']
        context_id = resp['result']['contextId']
    except Exception as e:
        # send reject payload and abort operations
        await A2ADidAuthService.send_did_auth_reject(
            cause=str(e)
        )
        raise SystemExit(f"A2ADIDAuth operations aborted: {e}")

    #* - A2ADIDAuth: PHASE 3 and 4
    try:
        # retrieve the private key from waltid wallet
        result = await alice.mcp_session.call_tool(
            name="export_key_jwk",
            arguments={"session": alice.waltid_session, "load_private": True}
        )
        private_key = rehydrate_after_mcp_tool_call(result, dict)

        resp = await A2ADidAuthService.send_did_auth_response(
            a2a_resp=resp,
            client_did=alice.did,
            nonce=nonce,
            signing_key_jwk=private_key
        )
    except Exception as e:
        # send reject payload and abort operations
        await A2ADidAuthService.send_did_auth_reject(
            task_id=task_id,
            context_id=context_id,
            cause=str(e)
        )
        raise SystemExit(f"A2ADIDAuth operations aborted: {e}")

    assert 1 == 1