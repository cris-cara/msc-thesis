from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Optional, Annotated, Literal, Union
from pydantic import BaseModel, Field, ConfigDict

class _BasePayload(BaseModel):
    #forbid => if an unexpected field arrives, an error is raised
    model_config = ConfigDict(extra="forbid")

class BeginPayload(_BasePayload):
    op: Literal["begin"]
    client_did: str
    nonce: str

class ResponsePayload(_BasePayload):
    op: Literal["response"]
    response_jws: str

class RejectionPayload(_BasePayload):
    op: Literal["reject"]

# discriminated union: chooses the right model by looking at payload["op"]
Payload = Annotated[
    Union[BeginPayload, ResponsePayload],
    Field(discriminator="op"),
]
