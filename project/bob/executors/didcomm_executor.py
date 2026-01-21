import json
import uuid
import bob.helpers.auth_utils as auth

from typing import Any, Dict, Optional

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import Message as A2AMessage, DataPart

from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from didcomm.common.resolvers import ResolversConfig

from openai import AzureOpenAI
from bob.mcp.hub import McpHub
from common import config, get_logger
from common.a2a_helpers import build_a2a_message_from_didcomm

# =================== CONFIG ===================
cfg = config()

ALICE_DID = cfg["DIDs"]["alice"]
BOB_DID = cfg["DIDs"]["bob"]

GREEN = cfg["colors"]["GREEN"]
BLUE = cfg["colors"]["BLUE"]
RED = cfg["colors"]["RED"]
RESET = cfg["colors"]["RESET"]

logger = get_logger(__name__)  # Get a logger instance

SYSTEM_PROMPT = """\
You are Bob. You receive messages from Alice and may use MCP tools to respond.

Language:
- Always respond in English, even if Alice writes in Italian
- It's a single shot query, just respond to the question with no further engagement.

Tool-use rules:
- If the request is about weather, use the tool weather.get_current_weather (pass the city).
- Never invent results: any factual data must come from MCP tool outputs.
- Use the minimum number of tool calls needed, then answer concisely.
"""
# ==============================================

# - ================== UTILS  ==================
def _validate_and_get_jwe(a2a_msg: A2AMessage):
    """
    Validates an A2AMessage and retrieves the JSON Web Encryption (JWE) payload.

    This function ensures that the provided A2AMessage has the required structure
    to contain a DIDComm JWE payload. It verifies the existence of the JWE payload
    within the message and returns it as a serialized JSON string. If the message
    is invalid or improperly structured, a RuntimeError is raised.

    Parameters:
    a2a_msg (A2AMessage): The A2A message to validate and extract the JWE payload from.
                          Must contain at least one part, and the root of the first part
                          must be of type DataPart with DIDComm payload.

    Returns:
    str: The serialized JSON string representation of the JWE payload.

    Raises:
    RuntimeError: If the A2A message has no parts, the root part is not a DataPart,
                  or if the JWE payload is missing from the DIDComm data.
    """
    if not a2a_msg.parts:
        raise RuntimeError("A2A message has no parts")

    root_part = a2a_msg.parts[0].root
    if not isinstance(root_part, DataPart):
        raise RuntimeError("Expected DataPart with DIDComm payload")

    didcomm_container = root_part.data.get("didcomm") or {}
    jwe_json = didcomm_container.get("jwe")
    if not jwe_json:
        raise RuntimeError("Missing 'jwe' inside didcomm data")

    jwe_str = json.dumps(jwe_json)
    return jwe_str

# - ============================================

class DIDCommExecutor(AgentExecutor):
    def __init__(self,
                 did: str,
                 llm_client: AzureOpenAI,
                 mcp_hub: McpHub,
                 azure_deployment: str,
                 llm_tools_allowlist: set[str],
                 resolvers_cfg: ResolversConfig
                 ):
        self.did = did
        self.llm = llm_client
        self.hub = mcp_hub
        self.deployment = azure_deployment
        self.allowed = llm_tools_allowlist # {"weather"}
        self.resolvers_cfg = resolvers_cfg
        self.system_prompt = SYSTEM_PROMPT
        self.messages = [{"role": "system", "content": self.system_prompt}] # initialize LLM's messages list

    async def _authorize_and_process_weather_request(self, token: Optional[str], user_msg: str) -> Dict[str, Any]:
        """
        Validates the provided access token and, if authorized, queries the LLM to produce the weather response.

        Behavior:
        - If `token` is missing: returns an Unauthorized error payload.
        - If `token` is invalid/expired: returns an Unauthorized error payload.
        - If `token` is valid: calls `self._query_llm(input_msg=user_msg)` and returns {"weather": ...}.
        - If LLM processing fails: returns a Processing error payload.
        """
        # GATE: check the token
        if not token:
            logger.info(f"{RED}Request blocked: no token provided.{RESET}")
            response_content = {
                "error": "Unauthorized",
                "details": "Missing access_token. Please perform VP login first."
            }

        elif not auth.verify_token(token):
            logger.info(f"{RED}Request blocked: invalid or expired token.{RESET}")
            response_content = {
                "error": "Unauthorized",
                "details": "Invalid or expired token."
            }

        else:
            # 3) IF AUTHORIZED -> Call the LLM
            logger.info(f"{GREEN}Valid token. Executing weather request...{RESET}")
            try:
                llm_output = await self._query_llm(input_msg=user_msg)
                response_content = {"weather": llm_output}
            except Exception as e:
                response_content = {"error": "Processing error", "details": str(e)}

        return response_content

    async def _query_llm(self, input_msg: str):
        """
        Queries the Large Language Model (LLM) with a user-provided message and processes the
        response accordingly. The function loops until the LLM produces a final response
        without invoking additional tool calls.

        Attributes:
            messages (list[dict]): A list of dictionaries representing the conversation
            history. Each entry contains the role (e.g., 'user', 'assistant'), the
            message content, and associated tool calls if any.
            llm (object): A reference to the LLM client used to generate responses.
            deployment (str): The specific deployment of the LLM model to use.
            hub (object): A reference to the hub that provides access to tools
            and manages interactions with the LLM's tool calls.

        Parameters:
            input_msg (str): The message provided by the user to query the LLM.

        Raises:
            RuntimeError: If the LLM does not produce any valid response after processing.

        Returns:
            str: The final LLM response to the user's query after processing all
            intermediate tool calls.
        """

        self.messages.append({"role": "user", "content": input_msg})
        llm_response = ""
        while True:
            # ask the llm to retrieve the weather forecast for the given city
            resp = self.llm.chat.completions.create(
                model=self.deployment,
                messages=self.messages,
                tools=self.hub.openai_tools_for({"weather"}),  # <-- ONLY Weather
                tool_choice="auto",
            )

            assistant = resp.choices[0].message

            # always save the assistant message (even if empty)
            self.messages.append(
                {
                    "role": "assistant",
                    "content": assistant.content or "",
                    "tool_calls": assistant.tool_calls,
                }
            )

            if assistant.content:
                llm_response = assistant.content

            # if there are no tool_calls -> final response
            if not assistant.tool_calls:
                break

            # otherwise run tool and continue
            for tc in assistant.tool_calls:
                log, tool_msg = await self.hub.call_from_openai_tool_call(tc)
                logger.info(log)
                self.messages.append(tool_msg)

        # check if the LLM has answered the query
        if not llm_response:
            raise RuntimeError("No response from LLM")

        return llm_response

    async def _build_didcomm_weather_response(self, jwe_str: str) -> dict:
        # 1) unpack DIDComm msg and retrieve the text message from Alice
        try:
            unpack_result = await unpack(
                resolvers_config=self.resolvers_cfg,
                packed_msg=jwe_str,
            )

            user_msg = unpack_result.message.body.get("message") # ex. "Ciao Bob, quale è il meteo a <city>?""
            logger.info(f"{BLUE}[USER]: {user_msg}{RESET}")
            # extract the token from the DIDComm message body
            token = unpack_result.message.body.get("access_token")
        except AttributeError:
            raise RuntimeError("Invalid DIDComm message: missing 'message' field")

        # 2) authorize and process the weather request (check if the token presented by the user is valid)
        logger.info(f"{BLUE}[TOKEN]: {token}{RESET}")
        response_content = await self._authorize_and_process_weather_request(token=token, user_msg=user_msg)

        # 3) build DIDComm response
        reply = DidcommMessage(
            id=str(uuid.uuid4()),
            type="example/1.0/weather-response",
            body=response_content,
            frm=self.did, # BOB DID
            to=[ALICE_DID],
        )

        pack_result = await pack_encrypted(
            resolvers_config=self.resolvers_cfg,
            message=reply,
            frm=self.did, # BOB DID
            to=ALICE_DID,
            sign_frm=None,
            pack_config=PackEncryptedConfig(
                protect_sender_id=False,
                forward=False,
            ),
        )

        # packed_msg is a JSON string with JWE
        return json.loads(pack_result.packed_msg)

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        # context.message is the A2A Message from Alice (message/send)
        a2a_msg: A2AMessage = context.message

        logger.info(
            f"\n{'=' * 10} Received JSON-RPC request from Alice {'=' * 10}\n"
            f"{a2a_msg}\n"
        )

        # validate and get the JWE payload
        jwe_str = _validate_and_get_jwe(a2a_msg)

        # process the DIDComm request and get the JWE reply
        reply_jwe = await self._build_didcomm_weather_response(jwe_str=jwe_str)

        # build the JSON RPC response from the DIDComm reply
        """Convention: matching is done via A2A `message_id`.
        Sender: remember which `message_id` was sent.
        Receiver: set `response_message_id = request_message_id` when building the A2A message response.
        Note: JSON-RPC `id` may differ; intentionally ignored it in this demo."""
        reply_a2a_msg = build_a2a_message_from_didcomm(
            jwe_json=reply_jwe,
            message_id=a2a_msg.message_id,  # the initial request's message_id chosen Alice (set `response_message_id = request_message_id`)
            context_id=context.context_id,
            task_id=context.task_id,
        )

        # send the A2A message response to Alice
        await event_queue.enqueue_event(reply_a2a_msg)

        logger.info(
            f"\n{'=' * 10} A2A message/send response sent to Alice {'=' * 10}\n"
            f"{reply_a2a_msg}\n"
        )

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue
    ) -> None:
        # as of now, I don't handle cancel
        raise Exception("Cancel not supported")
