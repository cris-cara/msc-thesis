# VC Callback Webhook Service

This project is a small **FastAPI** HTTP service that receives callback events (for example from Microsoft Entra Verified ID) and stores them in a **SQLite** database. It also exposes simple APIs to query the stored events.

The service is deployed on Azure App Service and is publicly available at:
> **https://callback-webhook.azurewebsites.net/**

You can configure external systems (for example, Microsoft Entra Verified ID) to send their callback `POST` requests directly to this URL.

---

## Project Structure

* `main.py` – FastAPI application, route definitions, database handling.
* `events.db` – SQLite database with the events table (can be recreated automatically).
* `requirements.txt` – Runtime dependencies (FastAPI, Uvicorn, Gunicorn, etc.).
* `pyproject.toml` – Project metadata (name, version, dependencies).

---

## Requirements

* Python 3.13 (or higher, as specified in `pyproject.toml`)
* `pip` or `uv` for managing Python packages
* A filesystem location where the SQLite database file can be created

---

## Local Setup and Run

1.  **Clone or download the project.**

2.  **(Recommended) Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    
    # On macOS/Linux:
    source .venv/bin/activate
    
    # On Windows:
    .venv\Scripts\activate
    ```
    or
    ```bash
    uv sync
    ```

    
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```


4.  **(Optional) Set the database path via environment variable:**
    If not set, a local `events.db` file will be created in the current directory.
    ```bash
    export DB=/absolute/path/to/events.db
    ```

5.  **Start the development server:**
    ```bash
    python main.py
    ```
    or
    ```bash
    uv run main.py
    ```

The application will be available at [http://localhost:8000](http://localhost:8000).

*Note: On first run, the service automatically creates the database and the events table if they do not exist.*

---

## Database Model

The `events` table stores the callback data.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | Integer | Primary key, autoincrement |
| `request_id` | Text | **Required**. Maps to `requestId` |
| `status` | Text | Maps to `requestStatus` |
| `timestamp` | Text | UTC timestamp (`YYYY-MM-DD HH:MM:SS`) |
| `state` | Text | Optional field from the payload |
| `subject` | Text | Optional field from the payload |
| `vcd_json` | Text | Serialized JSON of `verifiedCredentialsData` |

**Indexes:**
There is an index to speed up queries by `request_id` and `timestamp`:
```sql
CREATE INDEX IF NOT EXISTS idx_events_req_timestamp ON events(request_id, timestamp);
```

## API Documentation

### 1. Health Check
`GET /`

Simple health check endpoint. Returns a small JSON object indicating that the service is running.
Use this as a “wake-up” or status endpoint in external scripts or monitoring.

---

### 2. Receive Callback Events
`POST /`

Receives a JSON payload and stores an event in the database.

**Expected fields in request body:**
* `requestId` (required)
* `requestStatus` (optional)
* `state` (optional)
* `subject` (optional)
* `verifiedCredentialsData` (optional; if present, it is serialized and stored in `vcd_json`)

**Outcomes:**
* **Error:** Returns `400` if the body is not valid JSON or `requestId` is missing.
* **Success:** Stores an event row with the current UTC timestamp.

---

### 3. Latest Events
`GET /events/latest`

Returns the latest 10 events inserted into the database, ordered from newest to oldest.

**Response includes:**
* A `count` with the number of events returned.
* An `events` array with the event objects.

---

### 4. Events by `request_id`
`GET /events/{request_id}`

Returns all events associated with a specific `request_id`, ordered by timestamp ascending (oldest to newest).

**Outcomes:**
* **Not Found:** Returns `404` if no events are found for the ID.
* **Success:** Returns a JSON object containing the `request_id` and the list of events.

---

### 5. Purge All Events
`DELETE /purge`

Deletes all rows from the `events` table.

> ⚠️ **Warning:** This is a destructive endpoint. Use it with care.

The response includes the number of deleted rows.

---