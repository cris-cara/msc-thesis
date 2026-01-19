import sqlite3
from typing import Any, Optional

# implementation of the internal database to manage session states

DDL = """
CREATE TABLE IF NOT EXISTS sessions (
  request_id          TEXT PRIMARY KEY,
  state               TEXT NOT NULL,
  created_at          TEXT NOT NULL,
  expires_at          TEXT NOT NULL,
  expected_holder_did TEXT NOT NULL,
  status              TEXT NOT NULL,
  token_issued        INTEGER NOT NULL DEFAULT 0,
  used                INTEGER NOT NULL DEFAULT 0,
  last_update_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_status     ON sessions(status);
"""

class SessionDB:
    def __init__(self, path: str = "bob/vc_sessions.sqlite3"):
        self.path = path
        with self._conn() as c:
            c.executescript(DDL)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    # CREATE (o UPSERT)
    def upsert(self, s: dict[str, Any]) -> None:
        """
        Inserts or updates a session in the database based on the provided session data. If a session
        with the same `request_id` already exists, its values are updated; otherwise, a new session
        record is inserted.

        Args:
            s (dict[str, Any]): The session data dictionary containing the following keys:
                - request_id (str): Unique identifier of the request.
                - state (str): Current state of the session.
                - created_at (datetime): Timestamp when the session was created.
                - expires_at (datetime): Timestamp when the session will expire.
                - expected_holder_did (str): Expected holder DID (Decentralized Identifier).
                - status (str): Current status of the session.
                - token_issued (bool): Whether a token has been issued for the session.
                - used (bool): Whether the session has been used.
                - last_update_at (datetime): Timestamp of the last update to the session.

        """
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO sessions (
                  request_id, state, created_at, expires_at, expected_holder_did,
                  status, token_issued, used, last_update_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                  state=excluded.state,
                  created_at=excluded.created_at,
                  expires_at=excluded.expires_at,
                  expected_holder_did=excluded.expected_holder_did,
                  status=excluded.status,
                  token_issued=excluded.token_issued,
                  used=excluded.used,
                  last_update_at=excluded.last_update_at
                """,
                (
                    s["request_id"],
                    s["state"],
                    s["created_at"],
                    s["expires_at"],
                    s["expected_holder_did"],
                    s["status"],
                    1 if s["token_issued"] else 0,
                    1 if s["used"] else 0,
                    s["last_update_at"],
                ),
            )

    # READ
    def get(self, request_id: str) -> Optional[dict[str, Any]]:
        """
        Retrieves session details from the database based on the provided request ID.

        This method queries the sessions table to fetch a single record that matches
        the given request ID. If no matching record is found, the method returns None.
        Otherwise, the session details are returned as a dictionary containing
        various attributes related to the session.

        Args:
            request_id: The unique identifier of the session to retrieve.

        Returns:
            Optional[dict[str, Any]]: A dictionary containing the session attributes
            if a matching record is found; otherwise, None.
        """
        with self._conn() as c:
            r = c.execute("SELECT * FROM sessions WHERE request_id=?", (request_id,)).fetchone()
            if not r:
                return None
            return {
                "request_id": r["request_id"],
                "state": r["state"],
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "expected_holder_did": r["expected_holder_did"],
                "status": r["status"],
                "token_issued": bool(r["token_issued"]),
                "used": bool(r["used"]),
                "last_update_at": r["last_update_at"],
            }

    # UPDATE
    def set_status(self, request_id: str, status: str, last_update_at: str) -> None:
        """Updates the status of a session based on the provided request ID and status."""
        with self._conn() as c:
            c.execute(
                "UPDATE sessions SET status=?, last_update_at=? WHERE request_id=?",
                (status, last_update_at, request_id),
            )

    def mark_used(self, request_id: str, last_update_at: str) -> None:
        """Marks a session as used based on the provided request ID."""
        with self._conn() as c:
            c.execute(
                "UPDATE sessions SET used=1, last_update_at=? WHERE request_id=?",
                (last_update_at, request_id),
            )

    # UPDATE “safe” for grant_token (atomic)
    # Grant only if: state+holder match, not expired, not already issued/used.
    def grant_token_if_ok(
        self,
        request_id: str,
        state: str,
        expected_holder_did: str,
        now_iso: str,
        last_update_at: str,
    ) -> bool:
        """
        Checks whether a token can be granted for a session after validating multiple
        criteria and updates the session record accordingly.

        This method verifies the session's request ID, state, holder DID, expiration
        time, and other conditions to ensure that the token is eligible to be issued.
        If all conditions are met, it updates the session record in the database to
        mark the token as issued and adjusts its last update timestamp.

        Args:
            request_id (str): The unique identifier of the request associated with the
                session.
            state (str): The current state of the session, which must match the
                expected state for issuing the token.
            expected_holder_did (str): The expected Decentralized Identifier (DID) of
                the holder. Must match the DID stored in the session record.
            now_iso (str): The current timestamp in ISO format. Used to check if the
                session is valid and unexpired.
            last_update_at (str): The timestamp in ISO format indicating the last
                update time of the session. This value will be applied to the session
                record if the token is issued.

        Returns:
            bool: True if the token was successfully granted and the database was
            updated, False otherwise.
        """
        with self._conn() as c:
            cur = c.execute(
                """
                UPDATE sessions
                SET token_issued=1,
                    last_update_at=?
                WHERE request_id=?
                  AND state=?
                  AND expected_holder_did=?
                  AND token_issued=0
                  AND used=0
                  AND expires_at > ?
                """,
                (last_update_at, request_id, state, expected_holder_did, now_iso),
            )
            return cur.rowcount == 1


    def cleanup_expired(self, now_iso: str) -> None:
        """Removes expired sessions from the database."""
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso,))

    def delete(self, request_id: str) -> None:
        """Removes a session record from the database based on the provided request ID."""
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE request_id = ?", (request_id,))

    def reserve_token_issue(self, request_id: str, expected_holder_did: str, now_iso: str) -> bool:
        """
        Reserves a token issuance in the database for the provided request.

        This method updates the database to mark a session as having its token issued,
        if the request satisfies certain conditions. The session must have its
        presentation verified, not be used, not have a token issued already, and must
        not be expired. If all conditions are met, the session will be updated
        accordingly, and the method will return True.

        Args:
            request_id (str): The unique identifier for the request being processed.
            expected_holder_did (str): The decentralized identifier of the holder
                expected to match for the session.
            now_iso (str): The current time in ISO 8601 format. Used to check for
                expired sessions and update the last modification time.

        Returns:
            bool: True if the database was successfully updated (indicating the token
                has been reserved), False otherwise.
        """
        with self._conn() as c:
            cur = c.execute(
                """
                UPDATE sessions
                SET token_issued=1,
                    used=1,
                    last_update_at=?
                WHERE request_id=?
                  AND expected_holder_did=?
                  AND status='presentation_verified'
                  AND token_issued=0
                  AND used=0
                  AND expires_at > ?
                """,
                (now_iso, request_id, expected_holder_did, now_iso),
            )
            return cur.rowcount == 1

    def unreserve_token_issue(self, request_id: str, now_iso: str) -> None:
        """
        Unreserves a token issue by resetting the `token_issued` and `used` fields and updating
        the `last_update_at` timestamp for the specified request ID in the database.

        Args:
            request_id: The unique identifier for the request whose token issue status should
                be unreserved.
            now_iso: An ISO 8601 formatted string representing the current timestamp to be
                updated as `last_update_at`.
        """
        with self._conn() as c:
            c.execute(
                "UPDATE sessions SET token_issued=0, used=0, last_update_at=? WHERE request_id=?",
                (now_iso, request_id),
            )