# * Imagine that Eve, a MITM (main-in-the-middle), is able to steal the access token and wants to replay it, to get
# * Bob's AuthenticatedExtendedCard without being explicitly authorized nor authenticated

import ssl
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from didcomm.unpack import unpack

import alice.helpers as helpers
from common.a2a_helpers import build_a2a_send_request_from_didcomm
from common.config import config
from eve.__main__ import Eve

# =================== CONFIG ===================
BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"

cfg = config()
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BOB_DID = cfg["DIDs"]["bob"]
EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
# ==============================================


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
async def test_token_replay_in_didcomm_request(eve, bob_https: httpx.AsyncClient):
    # ! access token stolen from Alice
    # ! NOTE: execute alice.__main__ script and print the token to stole it
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJbU55ZGlJNklsQXRNalUySWl3aWEybGtJam9pWkRRNVVGQXpRMm95Y25Rd1gwUmhhMnN0TjNWdlF6RnBTMUk1UVhOclFrcElOMWxyVEZGWFJXOXZVU0lzSW5naU9pSkZRelpJUnpoT1dsWkxTeTFFYVZWUVkzTmtXa3RuVUd4eGJVcEZNVlZIWm1Kc2JrUndTSEJqY1Racklpd2llU0k2SWpCZlYxbHJOMmxqTWsxMmVrZDFXV0p0T1dKQmNqTTBWa3hrYjJGNFZuZHNjVlpVVGpWSU1taGxSbU1pZlEiLCJleHAiOjE3NzI3MzM3MTgsInR5cGUiOiJhY2Nlc3NfdG9rZW4ifQ.hUEP-mxZd2xLWEuO9j37GZS8B9pFWCqK3H2NLCupWPI"

    # 1) Build DIDComm JWE to send to Bob
    jwe_request_json = await helpers.build_didcomm_weather_request(
        sender_did=eve.did,
        city="Turin",
        # ! attach the access_token in the DIDComm message body
        access_token=access_token,
        resolvers_cfg=eve.resolvers_config
    )

    # 2) Wrap DIDComm JWE in A2A JSON-RPC request
    json_rpc_id = str(uuid.uuid4())
    jsonrpc_request = build_a2a_send_request_from_didcomm(
        json_rpc_id=json_rpc_id,
        didcomm_jwe_req=jwe_request_json,
    )

    # 3) POST to A2A server root via HTTPS
    # NOTE: set a large timeout to give Bob's LLM model time to respond
    try:
        resp = await bob_https.post(
            url=BOB_BASE_URL,
            json=jsonrpc_request,
            timeout=httpx.Timeout(30.0)
        )
        resp.raise_for_status()
        jsonrpc_response = resp.json()
    except httpx.HTTPStatusError as e:
        raise SystemExit(f"Unable to retrieve a response from Bob: {e}")

    # 4) Validate and unpack Bob's DIDComm reply
    jwe_reply_str = helpers.validate_and_get_jwe(
        target_json_rp_id=json_rpc_id,
        jsonrpc_response=jsonrpc_response
    )

    unpack_result = await unpack(
        resolvers_config=eve.resolvers_config,
        packed_msg=jwe_reply_str,
    )

    reply_msg = unpack_result.message
    body = reply_msg.body or {}

    assert body and body == {'error': 'Unauthorized', 'details': 'Token subject does not match the sender DID in the DIDComm message.'}
