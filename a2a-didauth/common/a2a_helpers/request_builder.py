import uuid
from typing import Literal, Optional

Role = Literal["user", "agent"]

def build_a2a_request_from_didcomm(
    jwe_json: dict,
    *,
    role: Role = "user",
    message_id: Optional[str] = None,
    rpc_id: Optional[str] = None,
    task_id: Optional[str] = None,
    context_id: Optional[str] = None,
    message_metadata: Optional[dict] = None,
    request_metadata: Optional[dict] = None,
) -> dict:
    """
    Builds a JSON-RPC request for sending a DIDComm encrypted message.

    This function constructs a properly formatted JSON-RPC request payload
    for sending a DIDComm encrypted message with optional metadata and
    custom identifiers. It allows specification of various identifiers
    that can be used for task tracking and message contextualization.

    Parameters:
        jwe_json (dict): The JWE formatted as a dictionary that represents the
            encrypted DIDComm message.
        role (Role): The role of the sender for the message. Defaults to "user".
        message_id (Optional[str]): A unique identifier for the message. If not
            provided, a UUID will be generated automatically.
        rpc_id (Optional[str]): A unique identifier for the JSON-RPC request. If
            not provided, a UUID will be generated automatically.
        task_id (Optional[str]): An optional identifier associated with a task.
        context_id (Optional[str]): An optional identifier to provide context for
            the message.
        message_metadata (Optional[dict]): Additional metadata related to the message.
        request_metadata (Optional[dict]): Additional metadata for the JSON-RPC request.

    Returns:
        dict: A dictionary representing the JSON-RPC request payload.
    """

    message_id = message_id or uuid.uuid4().hex
    rpc_id = rpc_id or str(uuid.uuid4())

    a2a_message = {
        "kind": "message",
        "role": role,
        "messageId": message_id,
        "parts": [{
            "kind": "data",
            "data": {
                "didcomm": {
                    "format": "application/didcomm-encrypted+json",
                    "jwe": jwe_json,
                }
            },
        }],
    }
    if task_id:
        a2a_message["taskId"] = task_id
    if context_id:
        a2a_message["contextId"] = context_id
    if message_metadata:
        a2a_message["metadata"] = message_metadata

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "message/send",
        "params": {
            "message": a2a_message,
            **({"metadata": request_metadata} if request_metadata else {}),
        },
    }
