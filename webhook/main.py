import os
import json
import sqlite3
import uvicorn
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# Percorso DB: puoi cambiarlo o usare una env var in Azure (es. DB=/home/events.db)
DB_PATH = os.getenv("DB", "events.db")

app = FastAPI()


# ---------- Utilities DB ----------

def now_iso() -> str:
    """Timestamp UTC in formato compatibile con ORDER BY datetime(...)."""
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def connect() -> sqlite3.Connection:
    """Apre una connessione SQLite."""
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    return con


def ensure_db() -> None:
    """Crea il DB e la tabella se non esistono."""
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
          vcd_json   TEXT      -- verifiedCredentialsData serializzato
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
    Wake-up call della webapp su Azure. Da script issuance/verification:
    - controllare se status == "running" altrimenti raise Exception
    """
    return JSONResponse({"status": "running"})

@app.post("/")
async def receive(request: Request):
    """
    Riceve il POST da MS Entra (o chiunque).
    Salva: requestId, requestStatus, state, subject, verifiedCredentialsData.
    Alcuni campi possono mancare o essere stringhe vuote.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body non è JSON valido")

    request_id = payload.get("requestId")
    if not request_id:
        raise HTTPException(status_code=400, detail="requestId mancante")

    # Campi opzionali
    status = payload.get("requestStatus") or None
    state = payload.get("state") or None
    subject = payload.get("subject") or None

    # verifiedCredentialsData può mancare
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
    Restituisce gli ultimi 10 eventi, ordinati dal più recente al meno recente.
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

    # anche se non ci sono eventi restituiamo 200 con lista vuota
    return JSONResponse({"count": len(events), "events": events})

@app.get("/events/{request_id}")
def read_by_request_id(request_id: str):
    """
    Restituisce tutti gli eventi per quel request_id,
    ordinati per timestamp crescente.
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
        raise HTTPException(status_code=404, detail="request_id non trovato")

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
    Cancella tutti i record dalla tabella events.
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
