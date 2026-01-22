import uuid
from typing import Optional

from a2a.types import (
    Part,
    DataPart,
    Task,
    TaskStatus,
    TaskState, Artifact,
)

from common.config import config

# =================== CONFIG ===================
cfg = config()

DIDCOMM_FORMAT = cfg["A2A"]["didcomm_format"]
# ==============================================

def build_a2a_response_task_from_didcomm(
    task_state: TaskState,
    didcomm_jwe_resp: dict,
    *,
    task_id: Optional[str] = None,
    context_id: Optional[str] = None,
    metadata: Optional[dict] = None,
):
    """
    Builds a task object representing an a2a response from a DIDComm message.

    This function is designed to create a Task object containing details about an
    a2a response constructed using a DIDComm JWE payload. The task encapsulates
    contextual information, metadata, and artifacts related to the provided DIDComm
    response. This structure allows for consistent representation and handling of
    responses within a task-oriented system.

    Parameters:
    task_state (TaskState): Represents the state of the task (e.g., pending, completed).
    didcomm_jwe_resp (dict): The DIDComm JWE response payload.
    task_id (Optional[str], optional): The unique identifier for the task. Defaults to None.
    context_id (Optional[str], optional): A contextual identifier for the task, allowing linkage to higher-level
                                           operations or workflows. Defaults to None.
    metadata (Optional[dict], optional): Additional metadata to include in the task. Defaults to None.

    Returns:
    Task: An object that encapsulates the provided DIDComm response details, task state,
              metadata, and associated artifacts.
    """
    data = {
        "didcomm":
            {
                "format": DIDCOMM_FORMAT,
                "jwe": didcomm_jwe_resp
            }
    }

    didcomm_artifact = Artifact(
        artifact_id=str(uuid.uuid4()),
        name="didcomm_response",
        parts=[
            Part(
                root=DataPart(
                    data=data
                )
            )
        ],
    )

    task = Task(
        id=task_id,
        context_id=context_id,
        status=TaskStatus(
            state=task_state
        ),
        artifacts = [didcomm_artifact],
        metadata=metadata,
    )

    return task