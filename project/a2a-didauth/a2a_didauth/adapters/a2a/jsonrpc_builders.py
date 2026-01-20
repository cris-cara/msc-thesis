import uuid
from typing import overload, Optional, Literal, Union

from a2a.types import (
    Message,
    MessageSendParams,
    SendMessageRequest,
)
from a2a.types import (
    Message as A2AMessage,
    Part,
    DataPart,
    Task,
    TaskStatus,
    TaskState, Role,
)

from a2a_didauth.core.models import BeginPayload, RejectionPayload, ResponsePayload
from a2a_didauth.core.session import DIDAuthSession


def build_json_rpc_message(
        ext_uri: str,
        payload: Union[BeginPayload, ResponsePayload, RejectionPayload],
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        *,
        cause: Optional[str] = None
) -> dict:
    """
    Builds a JSON-RPC message object based on the provided external URI, payload, and optional parameters.

    This function constructs a properly formatted JSON-RPC object for message-related actions,
    including optional rejection causes, task identifiers, and context identifiers. The generated
    message object adheres to the existing structure of the JSON-RPC protocol.

    Arguments:
        ext_uri: The external URI that acts as an identifier for the message's context.
        payload: A payload object of type BeginPayload, ResponsePayload, or RejectionPayload,
            containing the data to be conveyed in the message.
        task_id: An optional string that represents the task identifier associated with the message.
        context_id: An optional string that represents the contextual environment for the message.
        cause: An optional string to specify the cause when the payload is of type RejectionPayload.

    Returns:
        A dictionary representing the JSON-RPC message, serialized to the required JSON format.
    """
    ext_payload = payload.model_dump(mode="json")

    # craft eventual data payload with cause of rejection
    data_payload: dict = {}
    if type(payload) == RejectionPayload and isinstance(cause, str):
        data_payload["cause"] = cause

    data = {ext_uri: data_payload} if data_payload else {}

    msg = Message(
        message_id=str(uuid.uuid4()),
        role=Role.user,
        task_id=task_id,
        context_id=context_id,
        parts=[
            Part(
                root=DataPart(
                    data=data
                )
            )
        ],
        extensions=[ext_uri],
    )

    req = SendMessageRequest(
        id=str(uuid.uuid4()),
        params=MessageSendParams(
            message=msg,
            metadata={ext_uri: ext_payload},
        ),
    )

    json_rpc = req.model_dump(mode="json", exclude_none=True)

    return json_rpc


@overload
def build_json_rpc_task(
        ext_uri: str,
        op: Literal["challenge"],
        session: DIDAuthSession,
        jws_challenge: str,
        *,
        cause: None = None
) -> Task: ...
    #                 op = "challenge"  => jws_challenge MUST be str (not None)

@overload
def build_json_rpc_task(
        ext_uri: str,
        op: Literal["complete"],
        session: DIDAuthSession,
        jws_challenge: None = None,
        *,
        cause: None = None
) -> Task: ...
    #                 op = "complete"   => jws_challenge MUST be None (or omitted)

@overload
def build_json_rpc_task(
        ext_uri: str,
        op: Literal["reject"],
        session: DIDAuthSession,
        jws_challenge: None = None,
        *,
        cause: Optional[str] = None,
) -> Task: ...
    #                 op = "reject"   => jws_challenge MUST be None (or omitted)

def build_json_rpc_task(
        ext_uri: str,
        op: Literal["challenge", "complete", "reject"],
        session: DIDAuthSession,
        jws_challenge: Optional[str] = None,
        *,
        cause: Optional[str] = None,
    ) -> Task:
    """
    Constructs and returns a JSON-RPC `Task` object based on the input parameters and the desired operation.

    Raises an error if required parameters are missing for specific operations.

    Parameters:
        ext_uri (str): The external URI identifying the context of the task.
        op (Literal["challenge", "complete", "reject"]): The intended operation for the task. Valid operations
            are "challenge", "complete", and "reject".
        session (DIDAuthSession): The session object containing task-related identifiers and information.
        jws_challenge (Optional[str]): The JWS challenge payload. Required if the operation (`op`) is
            set to "challenge".
        cause (Optional[str], optional): An explanation or reason for the rejection, only applicable
            when the operation is "reject".

    Returns:
        Task: A JSON-RPC task object that encapsulates the operation, task status, unique identifiers,
            and message metadata.

    Raises:
        ValueError: If the operation is "challenge" and the `jws_challenge` is not provided.
    """
    if op == "challenge" and not jws_challenge:
        raise ValueError("jws_challenge is required when op='challenge'")

    data_payload: dict = {}
    if op == "reject" and isinstance(cause, str):
        data_payload["cause"] = cause

    if op == "challenge":
        data_payload["challenge_jws"] = jws_challenge

    data = {ext_uri: data_payload} if data_payload else {}

    task = Task(
        id=session.task_id,
        context_id=session.context_id,
        status=TaskStatus(
            state=(
                TaskState.completed if op == "complete"
                else TaskState.rejected if op == "reject"
                else TaskState.input_required
            ),
            message=A2AMessage(
                kind="message",
                message_id=str(uuid.uuid4()),
                role=Role.agent,
                parts=[
                    Part(
                        root=DataPart(
                            data=data
                        )
                    )
                ],
            ),
        ),
        metadata={
            ext_uri: {
                "op": op,
            }
        },
    )

    return task