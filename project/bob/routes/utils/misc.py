import httpx
import bob.helpers as helpers

from common import config
from typing import Any, Dict, Optional, Iterable
from datetime import datetime, timedelta, timezone
from starlette.requests import Request

# =================== CONFIG ===================
cfg = config()

CALLBACK_URL = cfg["MSEntraID"]["callback_url"]

# Fallback TTL
_DEFAULT_TTL_SECONDS = int("300") # seconds

_TS_FMT = "%Y-%m-%d %H:%M:%S"
# ==============================================

def now_utc() -> datetime:
    """Returns the current UTC datetime."""
    return datetime.now(timezone.utc)

def parse_expiry(value: Any) -> Optional[datetime]:
    """
    Try converting expiry to UTC datetime. Supports:
    - ISO string (with Z or offset)
    - epoch seconds (int/float)
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None

    if isinstance(value, str):
        s = value.strip()
        # ISO con Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    return None

async def read_json(request: Request) -> Dict[str, Any]:
    """Parses JSON data from the request body."""
    try:
        data = await request.json()
    except Exception:
        raise ValueError("Invalid JSON body")
    if not isinstance(data, dict):
        raise ValueError("JSON body must be an object")
    return data


def require_request_id(pres_req: Dict[str, Any]) -> str:
    """Extracts the request ID from a presentation request response."""
    rid = pres_req.get("requestId") or pres_req.get("request_id")
    if not isinstance(rid, str) or not rid.strip():
        raise RuntimeError("Presentation request response missing requestId")
    return rid.strip()


def require_expires_at(pres_req: Dict[str, Any], now: datetime) -> datetime:
    """Extracts the expiration time from a presentation request response."""
    expires_at = parse_expiry(pres_req.get("expiry"))
    if expires_at is None:
        expires_at = now + timedelta(seconds=_DEFAULT_TTL_SECONDS)
    return expires_at


def create_presentation_request_secure(*, state: str) -> Dict[str, Any]:
    """Wrapper for helpers.create_presentation_request() to enforce correlation"""
    try:
        return helpers.create_presentation_request(state=state)
    except TypeError as e:
        raise RuntimeError(
            "helpers.create_presentation_request must accept (state) to enforce correlation"
        ) from e

def _parse_ts_strict(ts: Optional[str]) -> Optional[datetime]:
    """Parses a timestamp string in the strict format used by MS Entra ID."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts, _TS_FMT)
    except ValueError:
        return None

def check_callback(
    expected_request_id: str,
    expected_state: str,
    expected_subject: Optional[str],
) -> bool:
    """
    Checks if the latest callback event matches the expected criteria.

    This function retrieves callback events for a specific request ID, validates and
    parses their timestamps, and determines if the most recent event matches the
    provided state and subject criteria. The latest event is selected based on the
    maximum timestamp and event ID.

    Args:
        expected_request_id: The request ID for which callback events should be checked.
        expected_state: The expected state of the event to validate.
        expected_subject: The expected subject of the event to validate. Can be None
            if no specific subject criteria should be applied.

    Returns:
        True if the latest matching event satisfies the given criteria, False otherwise.
    """
    try:
        resp = httpx.get(
            url=f"{CALLBACK_URL}events/{expected_request_id}",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return False

    rows = data.get("events") or []
    if not rows:
        return False

    # keep only events with STRICT timestamps
    valid = []
    for e in rows:
        ts = _parse_ts_strict(e.get("timestamp"))
        if ts is None:
            continue
        try:
            eid = int(e.get("id") or 0)
        except Exception:
            eid = 0
        valid.append((ts, eid, e))

    if not valid:
        return False

    # last event: max by timestamp, then by id
    _, _, last = max(valid, key=lambda x: (x[0], x[1]))

    if last.get("status") != "presentation_verified":
        return False
    if last.get("request_id") != expected_request_id:
        return False
    if last.get("state") != expected_state:
        return False
    if expected_subject is not None and last.get("subject") != expected_subject:
        return False

    return True