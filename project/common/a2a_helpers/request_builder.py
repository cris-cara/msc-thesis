import uuid
from typing import Optional

from a2a.types import (
    Message,
    MessageSendParams,
    SendMessageRequest,
)
from a2a.types import (
    Part,
    DataPart,
    Role,
)

from common.config import config

# =================== CONFIG ===================
cfg = config()

DIDCOMM_FORMAT = cfg["A2A"]["didcomm_format"]
# ==============================================

def build_a2a_send_request_from_didcomm(
    json_rpc_id: str,
    didcomm_jwe_req: dict,
    *,
    role: Optional[Role] = Role.user,
    task_id: Optional[str] = None,
    context_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Builds an A2A (agent-to-agent) send request from a DIDComm (Decentralized Identifier Communication)
    JSON Web Encryption (JWE) request.

    This function constructs a properly formatted dictionary representing an A2A send request
    using the given DIDComm JWE request and other optional parameters such as role, task ID, context
    ID, and metadata. The function creates a hierarchical message structure, converts it into the required
    JSON-RPC format, and returns a serialized representation of the request.

    Args:
        json_rpc_id (str): A unique identifier for the JSON-RPC request.
        didcomm_jwe_req (dict): The DIDComm JWE object containing the core payload and associated encryption.
        role (Optional[Role]): Specifies the role, with a default value of Role.user.
        task_id (Optional[str]): Optional task identifier to associate with the message.
        context_id (Optional[str]): Optional context identifier for the message's processing scope.
        metadata (Optional[dict]): Additional metadata to include in the request payload.

    Returns:
        dict: A dictionary representing the A2A send request in JSON-RPC format, excluding any fields with None values.
    """
    data = {
        "didcomm":
            {
                "format": DIDCOMM_FORMAT,
                "jwe": didcomm_jwe_req
            }
    }

    msg = Message(
        message_id=str(uuid.uuid4()),
        role=role,
        task_id=task_id,
        context_id=context_id,
        parts=[
            Part(
                root=DataPart(
                    data=data
                )
            )
        ],
    )

    json_rpc = SendMessageRequest(
        id=json_rpc_id,
        params=MessageSendParams(
            message=msg,
            metadata=metadata,
        ),
    )

    a2a_didcomm_request = json_rpc.model_dump(mode="json", exclude_none=True)

    return a2a_didcomm_request
