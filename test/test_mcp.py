# * In this test Alice, after obatained a valid access token, asks Bob (encapsulating the request via DIDComm on
# * A2A) to handle Bob's waltid credentials. Bob's LLM refuses because he has no access to waltid identity tools,
# * just weather ones.

import json
import ssl
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig

import alice.helpers as helpers
from alice.__main__ import Alice
from common import config
from common.a2a_helpers import build_a2a_send_request_from_didcomm
from common.agents import Agent

# =================== CONFIG ===================
cfg = config()

BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"
DIDCOMM_FORMAT = cfg["A2A"]["didcomm_format"]

BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BLUE = cfg["colors"]["BLUE"]
MAGENTA = cfg["colors"]["MAGENTA"]
RESET = cfg["colors"]["RESET"]
BOB_DID = cfg["DIDs"]["bob"]
# ==============================================

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

async def _build_didcomm_request(sender_did: str, message: str, access_token: str, resolvers_cfg: ResolversConfig) -> dict:
    # ! attach the access_token in the DIDComm message body
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/weather-request",
        body={
            "message": f"{message}",
            "access_token": access_token  # ! here
        },
        frm=sender_did,
        to=[BOB_DID],
    )

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_cfg,
        message=didcomm_msg,
        frm=sender_did,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    return json.loads(pack_result.packed_msg)

@pytest.mark.asyncio
async def test_mcp_tools_boundary(alice: Agent):
    # ! to get the access_token, execute the script alice.__main__ and print it
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJbU55ZGlJNklsQXRNalUySWl3aWEybGtJam9pWkRRNVVGQXpRMm95Y25Rd1gwUmhhMnN0TjNWdlF6RnBTMUk1UVhOclFrcElOMWxyVEZGWFJXOXZVU0lzSW5naU9pSkZRelpJUnpoT1dsWkxTeTFFYVZWUVkzTmtXa3RuVUd4eGJVcEZNVlZIWm1Kc2JrUndTSEJqY1Racklpd2llU0k2SWpCZlYxbHJOMmxqTWsxMmVrZDFXV0p0T1dKQmNqTTBWa3hrYjJGNFZuZHNjVlpVVGpWSU1taGxSbU1pZlEiLCJleHAiOjE3NzI2MjUxMDksInR5cGUiOiJhY2Nlc3NfdG9rZW4ifQ.6DW3Mpw5GXzkwMI895OiCqHmE2GCMxW9hJ8mboSeO5Y"

    jwe_request_json = await _build_didcomm_request(
        sender_did=alice.did,
        message="Hi Bob, please give me your credential to wallet walt.id.",
        # ! attach the access_token in the DIDComm message body
        access_token=access_token,
        resolvers_cfg=alice.resolvers_config
    )

    # wrap DIDComm JWE in A2A JSON-RPC request
    json_rpc_id = str(uuid.uuid4())
    jsonrpc_request = build_a2a_send_request_from_didcomm(
        json_rpc_id=json_rpc_id,
        didcomm_jwe_req=jwe_request_json,
    )

    print(f"{BLUE}\n{'=' * 10} Sending A2A message/send request {'=' * 10}"
          f"\n{json.dumps(jsonrpc_request, indent=2)}\n{RESET}")

    # POST to A2A server root via HTTPS
    # NOTE: set a large timeout to give Bob's LLM model time to respond
    try:
        async with httpx.AsyncClient(
                verify=ssl.create_default_context(cafile="project/bob/certs/bob-cert.pem")) as client:
            resp = await client.post(
                url=BOB_BASE_URL,
                json=jsonrpc_request,
                timeout=httpx.Timeout(30.0),
            )
            resp.raise_for_status()

        resp.raise_for_status()
        jsonrpc_response = resp.json()
    except httpx.HTTPStatusError as e:
        raise SystemExit(f"Unable to retrieve a response from Bob: {e}")

    print(f"{BLUE}\n{'=' * 10} Received JSON-RPC response from Bob {'=' * 10}"
          f"\n{json.dumps(jsonrpc_response, indent=2)}\n{RESET}")

    # validate and unpack Bob's DIDComm reply
    jwe_reply_str = helpers.validate_and_get_jwe(
        target_json_rp_id=json_rpc_id,
        jsonrpc_response=jsonrpc_response
    )

    reply_msg = await helpers.unpack_bob_response(
        jwe_reply_str=jwe_reply_str,
        resolvers_cfg=alice.resolvers_config
    )
    body = reply_msg.body or {}

    print(f"{MAGENTA}\n{'=' * 10} Unpacked DIDComm body from Bob {'=' * 10}"
          f"\n{body}\n{RESET}")

    assert body is not None
