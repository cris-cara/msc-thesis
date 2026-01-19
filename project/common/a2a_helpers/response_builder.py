import uuid
from typing import Optional
from a2a.types import Message as A2AMessage, Part, DataPart, Role

def build_a2a_message_from_didcomm(
    jwe_json: dict,
    *,
    message_id: Optional[str] = None,
    task_id: Optional[str] = None,
    context_id: Optional[str] = None,
    metadata: Optional[dict] = None,
):
    """
    Builds an A2A message from a DIDComm JWE JSON payload.

    This function constructs an A2AMessage object using the provided DIDComm JWE
    JSON payload. It allows for optional customization of the message ID, task ID,
    context ID, and metadata. If the message ID is not provided, a new unique
    identifier is automatically generated. The function encapsulates the DIDComm
    payload in a specific format to ensure compatibility with A2A messaging systems.

    Arguments:
        jwe_json (dict): The DIDComm JWE JSON payload containing encrypted
            information to be included in the A2A message.
        message_id (Optional[str]): An optional unique identifier for the message.
            If not provided, a new one is generated.
        task_id (Optional[str]): An optional identifier for the task associated
            with the message.
        context_id (Optional[str]): An optional identifier for the context in which
            the message is being sent.
        metadata (Optional[dict]): Optional additional metadata to include with
            the message.

    Returns:
        A2AMessage: The constructed A2AMessage containing the encapsulated DIDComm
        JWE payload and any additional information provided.
    """
    message_id = message_id or uuid.uuid4().hex

    reply_data_part = DataPart(
        data={
            "didcomm": {
                "format": "application/didcomm-encrypted+json",
                "jwe": jwe_json,
            }
        }
    )

    return A2AMessage(
        role=Role.agent,
        message_id=message_id,
        parts=[Part(root=reply_data_part)],
        context_id=context_id,
        task_id=task_id,
        metadata=metadata,
    )
