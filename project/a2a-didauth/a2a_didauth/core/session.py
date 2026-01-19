from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Optional


class NonceDIDAuthStatus(StrEnum):
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    USED = "used"
    REJECTED = "rejected"

    @classmethod
    def _missing_(cls, value: object):  # type: ignore[override]
        # Backward-compat: early versions used "reject".
        if isinstance(value, str) and value == "reject":
            return cls.REJECTED
        return None


@dataclass
class DIDAuthSession:
    task_id: str
    context_id: str
    nonce: Optional[str] = None
    client_did: Optional[str] = None
    nonce_status: Optional[NonceDIDAuthStatus] = None


class DIDAuthSessionResolver(ABC):
    @abstractmethod
    def get(self, task_id: str) -> DIDAuthSession:
        pass

    @abstractmethod
    def put(self, task_id: str, session: DIDAuthSession) -> None:
        """Persist (or overwrite) the session stored under `task_id`."""
        pass

    @abstractmethod
    def mark_authenticated(self, task_id: str) -> None:
        pass

    @abstractmethod
    def mark_rejected(self, task_id: str) -> None:
        pass

    @abstractmethod
    def mark_used(self, task_id: str) -> None:
        pass


class DIDAuthSessionResolverDemo(DIDAuthSessionResolver):
    def __init__(self, path: str = "./didauth_sessions.json"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._atomic_write({})

    # ---------- internal helpers ----------

    def _load_all(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return {}
        try:
            raw = self._path.read_text(encoding="utf-8").strip()
            if not raw:
                return {}
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Invalid sessions file: root must be a JSON object (dict).")
            # ensure keys are strings and values are dict-like
            out: dict[str, dict[str, Any]] = {}
            for k, v in data.items():
                if isinstance(k, str) and isinstance(v, dict):
                    out[k] = v
            return out
        except json.JSONDecodeError:
            # corrupt or partially written file: better to explicitly fail
            raise ValueError(f"Invalid JSON in sessions file: {self._path}")

    def _atomic_write(self, data: dict[str, dict[str, Any]]) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        # atomic writing: tmp + replace
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=str(self._path.parent),
            encoding="utf-8",
        ) as tmp:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, self._path)

    @staticmethod
    def _serialize_session(session: DIDAuthSession) -> dict[str, Any]:
        return {
            "task_id": session.task_id,
            "context_id": session.context_id,
            "nonce": session.nonce,
            "client_did": session.client_did,
            "status": session.nonce_status.value,  # StrEnum -> string
        }

    @staticmethod
    def _deserialize_session(task_id: str, obj: dict[str, Any]) -> DIDAuthSession:
        try:
            # Backward-compat: if task_id/context_id weren't stored yet, recover
            # `task_id` from the JSON map key and default `context_id` to "".
            return DIDAuthSession(
                task_id=str(obj.get("task_id") or task_id),
                context_id=str(obj.get("context_id") or ""),
                nonce=str(obj["nonce"]),
                client_did=str(obj["client_did"]),
                nonce_status=NonceDIDAuthStatus(
                    str(obj.get("status", NonceDIDAuthStatus.PENDING.value))
                ),
            )
        except KeyError as e:
            raise ValueError(f"Missing field in stored session: {e}") from e
        except Exception as e:
            raise ValueError(f"Invalid stored session format: {obj}") from e

    def _update_status(self, task_id: str, status: NonceDIDAuthStatus) -> None:
        data = self._load_all()
        if task_id not in data:
            raise KeyError(f"Unknown task_id: {task_id}")
        data[task_id]["status"] = status.value
        self._atomic_write(data)

    # ---------- public API ----------

    def get(self, task_id: str) -> DIDAuthSession:
        data = self._load_all()
        if task_id not in data:
            raise KeyError(f"Unknown task_id: {task_id}")
        return self._deserialize_session(task_id, data[task_id])

    def put(self, task_id: str, session: DIDAuthSession) -> None:
        data = self._load_all()
        # Keep the stored representation consistent.
        if session.task_id != task_id:
            session = DIDAuthSession(
                task_id=task_id,
                context_id=session.context_id,
                nonce=session.nonce,
                client_did=session.client_did,
                nonce_status=session.nonce_status,
            )
        data[task_id] = self._serialize_session(session)
        self._atomic_write(data)

    def mark_authenticated(self, task_id: str) -> None:
        self._update_status(task_id, NonceDIDAuthStatus.AUTHENTICATED)

    def mark_rejected(self, task_id: str) -> None:
        self._update_status(task_id, NonceDIDAuthStatus.REJECTED)

    def mark_used(self, task_id: str) -> None:
        self._update_status(task_id, NonceDIDAuthStatus.USED)
