import os
import sqlite3
from datetime import datetime, timezone

# DB path: you can change it or use an env var in Azure (e.g. DB=/home/events.db)
DB_PATH = os.getenv("DB", "events.db")

def now_iso() -> str:
    """UTC timestamp in a format compatible with ORDER BY datetime(...)."""
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

def connect() -> sqlite3.Connection:
    """Open SQLite connection."""
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    return con

def ensure_db() -> None:
    """Create the DB and the table if they do not exist."""
    con = connect()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id TEXT    NOT NULL,
          status     TEXT,      -- requestStatus
          timestamp  TEXT    NOT NULL,
          state      TEXT,
          subject    TEXT,
          vcd_json   TEXT      -- serialized verifiedCredentialsData
        );

        CREATE INDEX IF NOT EXISTS idx_events_req_timestamp
          ON events(request_id, timestamp);
        """
    )
    con.commit()
    con.close()
