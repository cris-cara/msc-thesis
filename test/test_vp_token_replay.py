import json
import ssl
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig

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
async def eve_mitm():
    """ Initialize Eve man-in-the-middle (MITM) agent."""
    eve = Eve()
    await eve.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await eve.sign_in()
    eve.set_malignant_resolvers_config()

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
async def test_vp_token_replay_attack(eve_mitm, bob_https: httpx.AsyncClient):
    # * assume that the MITM stole a valid Microsoft Entra request_id and an entry of
    # * 'bob/didauth_sessions.json'
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
        "MS_request_id": "a13978f0-8b2d-498e-bfa8-197689ebf6b0",  # ! valid hardcoded request_id (stolen)
        # ! NOTE:it must be a request_id that exists in the vc_sessions.sqlite3 database; otherwise 404 error.
        # ! Since the db has an automatic cleanup function, if no records are present, to generate one simply
        # ! start the complete flow from alice.__main__
        "didauth_task_id": didauth_session_trace.get(key_trace).get("task_id"),
        "didauth_nonce": didauth_session_trace.get(key_trace).get("nonce"),
    }

    # * packing DIDComm message
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/vp-token-request",
        body=body,
        frm=eve_mitm.did,   #! packing with Eve's crypto material
        to=[BOB_DID],
    )

    jwe_request_json = await pack_encrypted(
        resolvers_config=eve_mitm.resolvers_config,
        message=didcomm_msg,
        frm=eve_mitm.did,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    # * send the payload to Bob
    resp = await bob_https.post(
        url="/getAccessToken",
        json=json.loads(jwe_request_json.packed_msg),
    )

    # ! see bob/routes/router.py (_get_access_token)
    assert resp.status_code == 403
    assert resp.json() == {"error": "Sender DID mismatch"}
