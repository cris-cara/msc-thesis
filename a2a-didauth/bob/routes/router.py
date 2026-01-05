import os
import uuid

from dotenv import load_dotenv
from .utils import *
from bob.helpers import auth_utils as auth
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, Router

# =================== CONFIG ===================
load_dotenv(".env", override=True)

_db = SessionDB(path="bob/bob_sessions.sqlite3")
CALLBACK_API_KEY = os.getenv("CALLBACK_API_KEY", "<api-key>")
# ==============================================

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

async def _get_access_token(request: Request) -> JSONResponse:
    """
    Handles the asynchronous generation of an access token based on the incoming request
    data and validation criteria.

    The function validates the incoming request payload, ensures the coherence between the
    subject DID and session data, checks the validity of the associated callback, and
    manages the issuance of access tokens. Database operations are carried out for cleanup,
    session verification, token reservation, and token issuance. Failures in validation or
    token generation are appropriately handled and corresponding error responses are
    returned.

    Args:
        request (Request): The incoming HTTP request containing payload data required for
            generating an access token.

    Returns:
        JSONResponse: A JSON response containing either the generated access token with its
            type or an error message with an appropriate HTTP status code.
    """
    try:
        body = await read_json(request)
        payload = GetAccessTokenIn.model_validate(body)
        incoming_subject_did = payload .did_subject.strip()
        incoming_request_id = payload .request_id.strip()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if not incoming_subject_did:
        return JSONResponse({"error": "did_subject is required"}, status_code=400)
    if not incoming_request_id:
        return JSONResponse({"error": "request_id is required"}, status_code=400)

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

    return JSONResponse({"access_token": token, "token_type": "Bearer"})

def build_router() -> Router:
    """Builds the Starlette router for the HTTP API endpoints."""
    return Router(
        routes=[
            Route("/getPresentationRequest", _get_presentation_request, methods=["POST"]),
            Route("/getAccessToken", _get_access_token, methods=["POST"]),
        ]
    )
