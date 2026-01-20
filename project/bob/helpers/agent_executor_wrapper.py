from typing import Any, Optional

from a2a.server.agent_execution import RequestContext
from a2a.types import (
    Message
)


def get_message(context: RequestContext) -> Message:
    """Best-effort extraction of the incoming A2A Message."""
    msg = getattr(context, "message", None)
    if msg is not None:
        return msg

    req = getattr(context, "request", None)
    if req is not None and getattr(req, "message", None) is not None:
        return req.message

    raise RuntimeError("RequestContext does not contain a message")

def get_metadata(context: RequestContext) -> dict[str, Any]:
    """Best-effort extraction of MessageSendParams.metadata."""
    # 1) some SDK versions expose it directly
    meta = getattr(context, "metadata", None)
    if isinstance(meta, dict):
        return meta

    # 2) official a2a-sdk keeps it on context.request.metadata
    req = getattr(context, "request", None)
    meta = getattr(req, "metadata", None) if req is not None else None
    if isinstance(meta, dict):
        return meta

    return {}

def get_task_id(context: RequestContext) -> Optional[str]:
    # official a2a-sdk: context.task_id
    tid = getattr(context, "task_id", None)
    if tid:
        return tid

    # fallback: context.request.configuration.task_id
    req = getattr(context, "request", None)
    cfg = getattr(req, "configuration", None) if req is not None else None
    return getattr(cfg, "task_id", None) or getattr(cfg, "taskId", None)

def get_context_id(context: RequestContext) -> Optional[str]:
    cid = getattr(context, "context_id", None)
    if cid:
        return cid

    req = getattr(context, "request", None)
    cfg = getattr(req, "configuration", None) if req is not None else None
    return getattr(cfg, "context_id", None) or getattr(cfg, "contextId", None)

def is_didauth_ext_activated(context: RequestContext, ext_uri: str) -> bool:
    """
    Determines if the DID Auth extension is activated within the given request context.

    This function checks whether the specified DID Auth extension URI is included in
    the requested extensions of the provided context. If the `requested_extensions`
    attribute is not a set, a `RuntimeError` is raised.

    Args:
        ext_uri (str): The URI of the extension for DID Auth
        context (RequestContext): The context object containing requested extensions.

    Returns:
        bool: True if the DID Auth extension is present in the `requested_extensions`,
        otherwise False.

    Raises:
        RuntimeError: If the `requested_extensions` attribute is missing or is not a
        set.
    """
    extensions = getattr(context, "requested_extensions", None)

    if not isinstance(extensions, set):
        raise RuntimeError("Missing requested_extensions")

    return ext_uri in extensions