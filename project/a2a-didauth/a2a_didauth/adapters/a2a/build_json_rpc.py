import uuid
from common.config import config
from a2a_didauth.core.models import BeginPayload
from typing import Optional
from a2a.types import (
    Message,
    Role,
    Part,
    DataPart,
    MessageSendParams,
    SendMessageRequest,
)

# =================== CONFIG ===================
cfg = config()

EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
# ==============================================

def build_json_rpc_message(payload: BeginPayload, task_id: Optional[str] = None, context_id: Optional[str] = None) -> dict:
    ext_payload = payload.model_dump(mode="json")

    msg = Message(
        message_id=str(uuid.uuid4()),
        role=Role.user,
        task_id=task_id,
        context_id=context_id,
        parts=[Part(root=DataPart(data={}))],
        extensions=[EXT_URI],
    )

    req = SendMessageRequest(
        id=str(uuid.uuid4()),
        params=MessageSendParams(
            message=msg,
            metadata={EXT_URI: ext_payload},
        ),
    )

    json_rpc = req.model_dump(mode="json", exclude_none=True)

    return json_rpc

def build_json_rpc_task():
    pass