from __future__ import annotations

import uuid
from os.path import sep

from jwcrypto import jwk, jws
import json
from dataclasses import dataclass
from typing import Any, Optional

from common.waltid_core import WaltIdSession
from bob.mcp.hub import McpHub
from common import config, rehydrate_after_mcp_tool_call
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue

from a2a.types import (
    Message,
    Part,
    DataPart,
    TextPart,
    Task,
    TaskStatus,
    TaskStatusUpdateEvent, TaskState, Role,
)

from a2a_didauth.core.session import (
    NonceDIDAuthStatus,
    DIDAuthSession,
    DIDAuthSessionResolver,
    DIDAuthSessionResolverDemo
)

from a2a_didauth.core.service import A2ADidAuthService


# =================== CONFIG ===================

# ==============================================

def _get_message(context: RequestContext) -> Message:
    """Best-effort extraction of the incoming A2A Message."""
    msg = getattr(context, "message", None)
    if msg is not None:
        return msg

    req = getattr(context, "request", None)
    if req is not None and getattr(req, "message", None) is not None:
        return req.message

    raise RuntimeError("RequestContext does not contain a message")

def _get_metadata(context: RequestContext) -> dict[str, Any]:
    """Best-effort extraction of MessageSendParams.metadata."""
    # 1) some SDK versions expose it directly
    meta = getattr(context, "metadata", None)
    if isinstance(meta, dict):
        return meta

    # 2) official a2a-sdk keeps it on context.request.metadata
    req = getattr(context, "request", None)
    meta = getattr(req, "metadata", None) if req is not None else None
    if isinstance(meta, dict):
        return meta

    return {}

def _get_task_id(context: RequestContext) -> Optional[str]:
    # official a2a-sdk: context.task_id
    tid = getattr(context, "task_id", None)
    if tid:
        return tid

    # fallback: context.request.configuration.task_id
    req = getattr(context, "request", None)
    cfg = getattr(req, "configuration", None) if req is not None else None
    return getattr(cfg, "task_id", None) or getattr(cfg, "taskId", None)

def _get_context_id(context: RequestContext) -> Optional[str]:
    cid = getattr(context, "context_id", None)
    if cid:
        return cid

    req = getattr(context, "request", None)
    cfg = getattr(req, "configuration", None) if req is not None else None
    return getattr(cfg, "context_id", None) or getattr(cfg, "contextId", None)

def _is_didauth_ext_activated(context: RequestContext, ext_uri: str) -> bool:
    """
    Determines if the DID Auth extension is activated within the given request context.

    This function checks whether the specified DID Auth extension URI is included in
    the requested extensions of the provided context. If the `requested_extensions`
    attribute is not a set, a `RuntimeError` is raised.

    Args:
        ext_uri (str): The URI of the extension for DID Auth
        context (RequestContext): The context object containing requested extensions.

    Returns:
        bool: True if the DID Auth extension is present in the `requested_extensions`,
        otherwise False.

    Raises:
        RuntimeError: If the `requested_extensions` attribute is missing or is not a
        set.
    """
    extensions = getattr(context, "requested_extensions", None)

    if not isinstance(extensions, set):
        raise RuntimeError("Missing requested_extensions")

    return ext_uri in extensions

class DidAuthExecutorWrapper(AgentExecutor):
    """Wraps an existing executor and intercepts the DID Auth profile-extension flow.

    Pattern:
    - If extension is not activated -> delegate to inner.
    - If activated:
      * First message (no taskId) -> create Task in INPUT_REQUIRED with a challenge.
      * Next message (same taskId) -> verify response and complete the task.

    No while/loop is needed: multi-turn is expressed through Task + subsequent message/send calls.
    """

    def __init__(
        self,
        inner: AgentExecutor,
        did: str,
        mcp_hub: McpHub,
        waltid_session: WaltIdSession,
        *,
        ext_uri: str,
        didauth_session_resolver: Optional[DIDAuthSessionResolver] = None
    ) -> None:
        self._inner = inner
        self._did = did
        self._mcp_hub=mcp_hub
        self._waltid_session = waltid_session
        self._ext_uri = ext_uri
        self._didauth_session_resolver = didauth_session_resolver

    async def get_signing_key_from_waltid(self):
        result = await self._mcp_hub.call(
            tool_alias="waltid.export_key_jwk",
            arguments={"session": self._waltid_session, "load_private": True}
        )
        private_key = rehydrate_after_mcp_tool_call(result, dict)

        return private_key

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # create the DIDAuthSessionResolver object
        if not self._didauth_session_resolver:
            self._didauth_session_resolver = DIDAuthSessionResolverDemo(path="bob/didauth_sessions.json")

        meta = _get_metadata(context)

        # - quick re-route to the inner executor (DIDComm flow) if DID Auth is not activated (or not properly activated)
        if not _is_didauth_ext_activated(context=context, ext_uri=self._ext_uri):
            await self._inner.execute(context, event_queue)
            return

        # Extension is activated: require extension-specific metadata container.
        ext_meta = meta.get(self._ext_uri)
        if not isinstance(ext_meta, dict):
            raise RuntimeError(
                f"Malformed metadata: expected metadata['{self._ext_uri}'] to be an object"
            )

        # get taskId and contextId that the A2A SDK automatically generate and create the DIDAuthSession
        didauth_session = DIDAuthSession(
            task_id=_get_task_id(context),
            context_id=_get_context_id(context),
        )

        # ------------------------ ROUTING DID Auth operations ------------------------
        op = ext_meta.get("op")
        if op not in ('begin', 'reject', 'response'):
            raise RuntimeError(f"Unknown did_auth op: {op}")

        if op == "reject":
            raise RuntimeError("DID Auth rejected by user")

        if op == "begin":
            # - A2ADIDAuth: PHASE 2
            client_did = ext_meta.get("client_did")
            nonce = ext_meta.get("nonce")
            if not client_did or not nonce:
                raise RuntimeError("Missing client_did or nonce in extension metadata")

            # update session
            didauth_session.client_did = client_did
            didauth_session.nonce = nonce
            didauth_session.nonce_status = NonceDIDAuthStatus.PENDING

            # retrieve signing key (private) from waltid
            signing_key_jwk = await self.get_signing_key_from_waltid()

            # build the task
            task = A2ADidAuthService.build_did_auth_challenge_task(
                iss_did=self._did,
                ext_uri=self._ext_uri,
                session=didauth_session,
                signing_key_jwk=signing_key_jwk
            )

            await event_queue.enqueue_event(task)

            # update the internal storage
            self._didauth_session_resolver.put(
                task_id=didauth_session.task_id,
                session=didauth_session
            )

            return

        if op == "response":
            # - A2ADIDAuth: PHASE 5
            response_jws = ext_meta.get("response_jws")
            if not response_jws:
                raise RuntimeError("Missing response_jws in extension metadata")

            print(response_jws)

            task = A2ADidAuthService.build_did_auth_verify_task(
                jws_response=response_jws
            )

            await event_queue.enqueue_event(task)
            return

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Delegate cancel to inner (if needed)
        await self._inner.cancel(context, event_queue)
