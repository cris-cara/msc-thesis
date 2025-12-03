import os
import json
import sqlite3
import uvicorn
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# DB path: you can change it or use an env var in Azure (e.g. DB=/home/events.db)
DB_PATH = os.getenv("DB", "events.db")

app = FastAPI()


# ---------- Utilities DB ----------
def now_iso() -> str:
    """UTC timestamp in a format compatible with ORDER BY datetime(...)."""
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def connect() -> sqlite3.Connection:
    """Open a SQLite connection."""
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


ensure_db()


# ---------- ROUTES ----------
@app.get("/")
async def root() -> JSONResponse:
    """
    Wake-up call for the Azure webapp. From the issuance/verification script:
    - check if status == "running" otherwise raise Exception
    """
    return JSONResponse({"status": "running"})

@app.post("/")
async def receive(request: Request):
    """
    Receive POST from MS Entra (or anyone).
    Store: requestId, requestStatus, state, subject, verifiedCredentialsData.
    Some fields may be missing or be empty strings.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body is not valid JSON")

    request_id = payload.get("requestId")
    if not request_id:
        raise HTTPException(status_code=400, detail="requestId is missing")

    # Optional fields
    status = payload.get("requestStatus") or None
    state = payload.get("state") or None
    subject = payload.get("subject") or None

    # verifiedCredentialsData may be missing
    vcd = payload.get("verifiedCredentialsData")
    vcd_json = json.dumps(vcd) if vcd is not None else None

    timestamp = now_iso()

    con = connect()
    try:
        con.execute(
            """
            INSERT INTO events (request_id, status, timestamp, state, subject, vcd_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_id, status, timestamp, state, subject, vcd_json),
        )
        con.commit()
    finally:
        con.close()

    return {
        "ok": True,
        "request_id": request_id,
        "timestamp": timestamp,
    }

@app.get("/events/latest")
def read_latest():
    """
    Return the last 10 events, ordered from most recent to least recent.
    """
    con = connect()
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT id, request_id, status, timestamp, state, subject, vcd_json
            FROM events
            ORDER BY datetime(timestamp) DESC
            LIMIT 10
            """
        ).fetchall()
    finally:
        con.close()

    events = []
    for r in rows:
        d = dict(r)
        vcd_json = d.pop("vcd_json", None)
        if vcd_json:
            try:
                d["verifiedCredentialsData"] = json.loads(vcd_json)
            except Exception:
                d["verifiedCredentialsData"] = None
        else:
            d["verifiedCredentialsData"] = None

        events.append(d)

    # even if there are no events we return 200 with an empty list
    return JSONResponse({"count": len(events), "events": events})

@app.get("/events/{request_id}")
def read_by_request_id(request_id: str):
    """
    Return all events for that request_id,
    ordered by ascending timestamp.
    """
    con = connect()
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT id, request_id, status, timestamp, state, subject, vcd_json
            FROM events
            WHERE request_id = ?
            ORDER BY datetime(timestamp) ASC
            """,
            (request_id,),
        ).fetchall()
    finally:
        con.close()

    if not rows:
        raise HTTPException(status_code=404, detail="request_id not found")

    events = []
    for r in rows:
        d = dict(r)
        vcd_json = d.pop("vcd_json", None)
        if vcd_json:
            try:
                d["verifiedCredentialsData"] = json.loads(vcd_json)
            except Exception:
                d["verifiedCredentialsData"] = None
        else:
            d["verifiedCredentialsData"] = None
        events.append(d)

    return JSONResponse({"request_id": request_id, "events": events})


@app.delete("/purge")
def purge():
    """
    Delete all records from the events table.
    """
    con = connect()
    try:
        cur = con.execute("DELETE FROM events")
        deleted = cur.rowcount
        con.commit()
    finally:
        con.close()

    return JSONResponse({"deleted": deleted})


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
