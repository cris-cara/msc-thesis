from typing import Optional

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue

import bob.helpers.a2a_context_utils as helpers
from a2a_didauth.adapters.a2a import build_json_rpc_task
from a2a_didauth.core.service import A2ADidAuthService
from a2a_didauth.core.session import (
    NonceDIDAuthStatus,
    DIDAuthSession,
    DIDAuthSessionResolver,
    DIDAuthSessionResolverDemo
)
from bob.mcp.hub import McpHub
from common import rehydrate_after_mcp_tool_call
from common.waltid_core import WaltIdSession


class A2ADidAuthExecutor(AgentExecutor):
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
        *,
        did: str,
        mcp_hub: McpHub,
        waltid_session: WaltIdSession,
        ext_uri: str,
        didauth_session_resolver: Optional[DIDAuthSessionResolver] = None
    ) -> None:
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

        meta = helpers.get_metadata(context)

        # Extension is activated: require extension-specific metadata container.
        ext_meta = meta.get(self._ext_uri)
        if not isinstance(ext_meta, dict):
            raise RuntimeError(
                f"Malformed metadata: expected metadata['{self._ext_uri}'] to be an object"
            )

        # get taskId and contextId that the A2A SDK automatically generate and create the DIDAuthSession
        didauth_session = DIDAuthSession(
            task_id=helpers.get_task_id(context),
            context_id=helpers.get_context_id(context),
        )

        #* ------------------------ ROUTING DID Auth operations ------------------------
        op = ext_meta.get("op")
        if op not in ('begin', 'reject', 'response'):
            raise RuntimeError(f"Unknown did_auth op: {op}")

        # instantiate the A2ADIDAuth service with the extension URI
        A2ADidAuthService.set_ext_uri(ext_uri=self._ext_uri)

        if op == "reject":
            print(context.message)

            # update the internal storage (mark nonce as rejected)
            self._didauth_session_resolver.mark_rejected(task_id=didauth_session.task_id)

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

            try:
                # retrieve signing key (private) from waltid
                signing_key_jwk = await self.get_signing_key_from_waltid()

                # build the task
                task = A2ADidAuthService.build_did_auth_challenge_task(
                    iss_did=self._did,
                    session=didauth_session,
                    signing_key_jwk=signing_key_jwk
                )
                print(task)

                await event_queue.enqueue_event(task)

                # update the internal storage
                self._didauth_session_resolver.put(
                    task_id=didauth_session.task_id,
                    session=didauth_session,
                )
            except Exception as e:
                # send reject Task and abort operations
                task = build_json_rpc_task(
                    ext_uri=self._ext_uri,
                    op="reject",
                    session=didauth_session,
                    cause=str(e)
                )

                await event_queue.enqueue_event(task)

                # update the internal storage (mark nonce as rejected)
                self._didauth_session_resolver.mark_rejected(task_id=didauth_session.task_id)

            return

        if op == "response":
            # - A2ADIDAuth: PHASE 5
            response_jws = ext_meta.get("response_jws")
            if not response_jws:
                raise RuntimeError("Missing response_jws in extension metadata")

            # retrieve session from internal storage
            current_session = self._didauth_session_resolver.get(task_id=didauth_session.task_id)

            try:
                task = A2ADidAuthService.build_did_auth_verify_task(
                    jws_response=response_jws,
                    session=current_session,
                    session_resolver=self._didauth_session_resolver,
                    server_did=self._did,
                )
                print(task)
                await event_queue.enqueue_event(task)

                # update the internal storage (mark nonce as authenticated)
                self._didauth_session_resolver.mark_authenticated(task_id=didauth_session.task_id)
            except Exception as e:
                # send reject Task and abort operations
                task = build_json_rpc_task(
                    ext_uri=self._ext_uri,
                    op="reject",
                    session=didauth_session,
                    cause=str(e)
                )

                await event_queue.enqueue_event(task)

                # update the internal storage (mark nonce as rejected)
                self._didauth_session_resolver.mark_rejected(task_id=didauth_session.task_id)

            return

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # as of now, I don't handle cancel
        raise Exception("Cancel not supported")
