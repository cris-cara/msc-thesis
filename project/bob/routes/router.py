import json
import os
import uuid
from functools import partial

from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from dotenv import load_dotenv
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, Router

from a2a_didauth.core.session import DIDAuthSessionResolverDemo, NonceDIDAuthStatus
from bob.helpers import auth_utils as auth
from bob.routes.utils import fetch_callback
from common import config
from .utils import *

# =================== CONFIG ===================
load_dotenv(".env", override=True)
cfg = config()

_db = SessionDB(path="bob/vc_sessions.sqlite3")
CALLBACK_API_KEY = os.getenv("CALLBACK_API_KEY", "<api-key>")
ALICE_DID = cfg["DIDs"]["alice"]
BOB_DID = cfg["DIDs"]["bob"]
# ==============================================

async def _encapsulate_token_in_didcomm_msg(token: str, resolvers_cfg: ResolversConfig) -> dict:
    """ Encapsulate the access token in a DIDComm message."""
    didcomm_token_env = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/access-token-response",
        body={"access_token": token},
        frm=BOB_DID,  # BOB DID
        to=[ALICE_DID],
    )

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_cfg,
        message=didcomm_token_env,
        frm=BOB_DID,  # BOB DID
        to=ALICE_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    # packed_msg is a JSON string with JWE
    return json.loads(pack_result.packed_msg)

async def _get_presentation_request(request: Request) -> JSONResponse:
    """
    Handles the creation and processing of a presentation request. This function verifies the request body,
    validates the expected holder DID, generates a random state, creates a secure presentation request,
    ensures the request's expiration details, stores the request details in the database, and returns
    the created presentation request as a JSON response.

    Args:
        request (Request): The incoming HTTP request object containing the body to
            be processed.

    Returns:
        JSONResponse: A JSON response containing the presentation request if
            successful, or an error message with the appropriate HTTP status code
            in case of failure.

    Raises:
        KeyError: If the presentation request lacks the necessary fields.
        ValueError: If the validation of the request body fails.
        Exception: If any other unexpected error occurs during processing.
    """
    now = now_utc()

    try:
        body = await read_json(request)
        expected_holder_did = PresentationRequestIn.model_validate(body).did_subject.strip()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if not expected_holder_did:
        return JSONResponse({"error": "did_subject is required"}, status_code=400)

    # pick a random state
    state = str(uuid.uuid4())

    try:
        pres_req = create_presentation_request_secure(state=state)
        request_id = require_request_id(pres_req)
        expires_at = require_expires_at(pres_req, now)

        # cleanup + write su DB
        now_iso = now.isoformat()
        _db.cleanup_expired(now_iso)

        _db.upsert({
            "request_id": request_id,
            "state": state,
            "created_at": now_iso,
            "expires_at": expires_at.isoformat(),
            "expected_holder_did": expected_holder_did,
            "status": "created",
            "token_issued": False,
            "used": False,
            "last_update_at": now_iso,
        })

        return JSONResponse(pres_req)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

async def _get_access_token(request: Request, resolvers_cfg: ResolversConfig) -> JSONResponse:
    """
    Handles the process of validating and issuing an access token based on a DIDComm message.

    Upon receiving a DIDComm message, the function unpacks it and validates the payload for the expected
    fields, ensuring coherence between the sender's DID and the did_subject. It verifies the authenticity
    of the nonce and performs database operations to manage token issuance.

    Attributes:
        None

    Parameters:
        request (Request): The HTTP request object containing the DIDComm message.
        resolvers_cfg (ResolversConfig): Configuration settings for the DIDComm message resolvers.

    Returns:
        JSONResponse: HTTP response with either the issued access token or an error message.

    Raises:
        StatusCodeException: Contains specific response codes and messages for different validation failures or errors.

    """
    # get the didcomm payload and unpack it
    jwe_request = await read_json(request)
    unpack_result = await unpack(
        resolvers_config=resolvers_cfg,
        packed_msg=jwe_request,
    )

    # retrieve the real DID of the sender and the body
    did_sender = unpack_result.message.frm.strip()
    body = unpack_result.message.body

    try:
        payload = GetAccessTokenIn.model_validate(body)
        incoming_subject_did = payload.did_subject.strip()
        incoming_request_id = payload.MS_request_id.strip()
        incoming_didauth_task_id = payload.didauth_task_id.strip()
        didauth_incoming_nonce = payload.didauth_nonce.strip()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if not incoming_subject_did:
        return JSONResponse({"error": "did_subject is required"}, status_code=400)
    if not incoming_request_id:
        return JSONResponse({"error": "request_id is required"}, status_code=400)
    if not incoming_didauth_task_id:
        return JSONResponse({"error": "didauth_task_id is required"}, status_code=400)
    if not didauth_incoming_nonce:
        return JSONResponse({"error": "nonce is required"}, status_code=400)

    now_iso = now_utc().isoformat()
    _db.cleanup_expired(now_iso)

    # retrieve the session associated with the request_id from the database
    sess = _db.get(incoming_request_id)
    if not sess:
        return JSONResponse({"error": "Unknown request_id"}, status_code=404)

    # check on the holder DID (coherence)
    expected_holder_did = sess.get("expected_holder_did")
    if expected_holder_did != incoming_subject_did:
        return JSONResponse({"error": "Holder mismatch"}, status_code=403)

    # retrieve the state for correlation with callback
    state = sess.get("state")
    if not state:
        return JSONResponse({"error": "Corrupted session: missing state"}, status_code=500)

    # check the callback (fail-early)
    if not check_callback(
        expected_request_id=incoming_request_id,
        expected_state=state,
        expected_subject=incoming_subject_did,
    ):
        return JSONResponse({"error": "Invalid callback"}, status_code=400)

    #! check if the nonce is authenticated and that corresponds to the incoming_holder_did
    #! check also if the sender in the didcomm unpacked message match the incoming_subject_did field
    try:
        didauth_session_resolver = DIDAuthSessionResolverDemo(path="bob/didauth_sessions.json")
        didauth_session = didauth_session_resolver.get(task_id=incoming_didauth_task_id)
        expected_nonce = didauth_session.nonce

        if not did_sender == incoming_subject_did:
            # if the actual sender of the didcomm msg IS NOT the one declared in the body 'did_subject' --> REPLAY ATTACK!
            return JSONResponse({"error": "Sender DID mismatch"}, status_code=403)

        if expected_nonce != didauth_incoming_nonce:
            return JSONResponse({"error": "Nonce mismatch"}, status_code=401)

        if didauth_session.nonce_status != NonceDIDAuthStatus.AUTHENTICATED:
            return JSONResponse({"error": "Session associated with this nonce not authenticated"}, status_code=401)

        if didauth_session.client_did != incoming_subject_did:
            return JSONResponse({"error": "Client DID mismatch"}, status_code=403)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    # ---------------- DB operations ----------------
    # mark the presentation with the associated request_id as verified
    _db.set_status(incoming_request_id, "presentation_verified", last_update_at=now_iso)

    # reserve token emission (atomic, one-time)
    reserved = _db.reserve_token_issue(
        request_id=incoming_request_id,
        expected_holder_did=incoming_subject_did,
        now_iso=now_iso,
    )
    if not reserved:
        return JSONResponse(
            {
                "error": f"Token already issued / session expired / not verified for request_id {incoming_request_id}"},
            status_code=409,
        )

    # issue token; roll back DB if it fails
    try:
        token = auth.create_access_token(incoming_subject_did)
    except Exception as e:
        _db.unreserve_token_issue(incoming_request_id, now_iso=now_utc().isoformat())
        return JSONResponse({"error": str(e)}, status_code=500)

    #! set nonce status to used and session.expires_at at the time the presented VC expires
    try:
        exp_date = fetch_callback.fetch_expiration_epoch(request_id=incoming_request_id) # in epoch
        # set nonce status to used
        didauth_session_resolver.mark_used(task_id=incoming_didauth_task_id)

        # set session.expires_at
        didauth_session_resolver.set_expiry(task_id=incoming_didauth_task_id, expires_at=exp_date)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    #! encapsulate the access token in a DIDComm message
    response = await _encapsulate_token_in_didcomm_msg(token=token, resolvers_cfg=resolvers_cfg)

    return JSONResponse(response, status_code=200)

def build_router(resolver_config: ResolversConfig) -> Router:
    """Builds the Starlette router for the HTTP API endpoints."""
    return Router(
        routes=[
            Route("/getPresentationRequest", _get_presentation_request, methods=["POST"]),
            Route("/getAccessToken", partial(_get_access_token, resolvers_cfg=resolver_config), methods=["POST"]),
        ]
    )
