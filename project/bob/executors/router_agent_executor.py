from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution import RequestContext
from a2a.server.events import EventQueue
from a2a.types import Message as A2AMessage, DataPart

import bob.helpers.a2a_context_utils as helpers
from common import config

# =================== CONFIG ===================
cfg = config()

DIDCOMM_FORMAT = cfg["A2A"]["didcomm_format"]
# ==============================================

class RouterAgentExecutor(AgentExecutor):
    def __init__(self,
                 a2a_didauth_executor: AgentExecutor,
                 didcomm_executor: AgentExecutor,
                 ext_uri: str
                ) -> None:
        self._didcomm_executor = didcomm_executor
        self._a2a_didauth_executor = a2a_didauth_executor
        self._ext_uri = ext_uri

    def is_didauth_flow(self, context: RequestContext) -> bool:
        """
        Determine if the specified request context corresponds to a DIDAuth flow.

        A DIDAuth (Decentralized Identifier Authentication) flow is determined based on the
        activation status in the request header, the presence of relevant metadata, and optional
        validation on the "op" (operation) field.

        Parameters:
            context (RequestContext): The context of the incoming request to analyze for DIDAuth flow.

        Returns:
            bool: True if the request corresponds to a DIDAuth flow, False otherwise.
        """

        # 1) check HEADER: if NOT enabled, it is not DIDAuth
        if not helpers.is_didauth_ext_activated(context=context, ext_uri=self._ext_uri):
            return False

        # 2) check METADATA: MUST BE metadata["ext_uri"]
        meta = helpers.get_metadata(context)
        ext_meta = meta.get(self._ext_uri)
        if not isinstance(ext_meta, dict):
            return False

        # 3) [optional] validation on the "op" field
        op = ext_meta.get("op")
        if op not in ("begin", "reject", "response"):
            return False

        return True

    @staticmethod
    def is_didcomm_message(context: RequestContext) -> bool:
        """
        Determines if the message context follows the DIDComm flow.

        Checks the structure and content of a message within the given
        context to identify whether it adheres to the DIDComm format.

        Returns:
            bool: True if the message follows the DIDComm flow, otherwise False.
        """
        # get the message from the context
        a2a_msg: A2AMessage = context.message

        parts = a2a_msg.parts
        if not isinstance(parts, list) or not parts:
            return False

        for part in parts:
            root = getattr(part, "root", None)
            if not isinstance(root, DataPart):
                continue

            data = root.data or {}
            didcomm_container = data.get("didcomm")
            if not isinstance(didcomm_container, dict):
                continue

            if didcomm_container.get("format") != DIDCOMM_FORMAT:
                continue

            jwe = didcomm_container.get("jwe")
            # jwe MUST be present and NOT empty
            if isinstance(jwe, dict) and jwe:
                return True

        return False


    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        #* -------------------------- ROUTING --------------------------
        # check if it's DIDAuth flow
        if self.is_didauth_flow(context=context):
            await self._a2a_didauth_executor.execute(context, event_queue)
            return

        # check if it's a DIDComm message
        if self.is_didcomm_message(context=context):
            await self._didcomm_executor.execute(context, event_queue)
            return

        # fallback
        raise RuntimeError(
            "Unsupported request: neither DIDAuth nor DIDComm. "
            "Expected DIDAuth metadata/op or DIDComm data.didcomm.jwe."
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # as of now, I don't handle cancel
        raise Exception("Cancel not supported")
