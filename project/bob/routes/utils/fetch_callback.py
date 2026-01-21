from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from common import config

# =================== CONFIG ===================
cfg = config()

CALLBACK_BASE_URL = cfg["MSEntraID"]["callback_url"]
# ==============================================

def _fetch_expiration_date(
    request_id: str,
    *,
    timeout: float = 10.0,
) -> Optional[str | datetime]:
    """Fetches the expiration date for a given request ID from the callback endpoint."""
    url = f"{CALLBACK_BASE_URL}/events/{request_id}"

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
    except (httpx.HTTPError, ValueError):
        return None

    events = payload.get("events") or []
    if not isinstance(events, list):
        return None

    # start from the latest event (usually the most recent one contains the verified data)
    for ev in reversed(events):
        if not isinstance(ev, dict):
            continue

        vcd = ev.get("verifiedCredentialsData")
        if not vcd:
            continue

        # verifiedCredentialsData can be a list of credentials or a single dict
        candidates: list[dict[str, Any]] = []
        if isinstance(vcd, dict):
            candidates = [vcd]
        elif isinstance(vcd, list):
            candidates = [x for x in vcd if isinstance(x, dict)]

        for cred in candidates:
            exp = cred.get("expirationDate")
            if isinstance(exp, str) and exp.strip():
                return exp

    return None


def fetch_expiration_epoch(request_id: str, *, timeout: float = 10.0) -> Optional[int]:
    """
    Fetches the expiration timestamp in epoch format based on the provided request ID.

    This function retrieves the expiration date for a given request ID, converts it to a timezone-aware
    UTC datetime object, and then calculates the corresponding epoch timestamp. If the expiration date
    retrieval or conversion fails, the function returns None.

    Args:
        request_id: A string representing the unique identifier of the request whose expiration
                    timestamp is to be retrieved.
        timeout: An optional float specifying the timeout duration for fetching the expiration date.
                 Defaults to 10.0 seconds.

    Returns:
        Optional[int]: The expiration time in epoch format as an integer if successful, or None
                       if the process fails.
    """
    expiration_date = _fetch_expiration_date(request_id, timeout=timeout)
    dt = datetime.fromisoformat(expiration_date.replace("Z", "+00:00")).astimezone(timezone.utc)

    if isinstance(dt, datetime):
        return int(dt.timestamp())

    return None
