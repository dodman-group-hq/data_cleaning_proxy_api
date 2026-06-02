# Dodman · Data Cleaning Proxy API

Stateless, in-memory CSV/XLSX cleaner. Upload a file, supply a column-rule config, get clean data back — or stream it to a webhook.

---

## Quick-start

```bash
# 1. Install deps
pip install fastapi uvicorn asyncpg httpx openpyxl python-dotenv python-multipart

# 2. Create .env (copy from .env.example)
cp .env.example .env   # then fill in values

# 3. Run
uvicorn main:app --reload
# → http://localhost:8000/docs
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `TENANT_DATABASE_URL` | Yes | asyncpg-compatible Postgres URL (e.g. Neon) |
| `INTERNAL_SERVICE_SECRET` | Yes | Shared secret protecting admin endpoints |

Both must be set before starting. The app logs a warning and disables auth endpoints if either is missing.

---

## Authentication

Every request to `/api/v1/clean` must include a valid API key as a Bearer token:

```
Authorization: Bearer dk_live_<your-key>
```

Keys are issued via the admin endpoint (see below).

---

## Endpoints

### `POST /api/v1/keys` — Issue an API key

**Who calls this:** you (the operator), from a secure backend or Postman — not end-users.

**Auth required:** `X-Internal-Secret` header matching `INTERNAL_SERVICE_SECRET`.

**Body:** `multipart/form-data` — **not JSON**.

| Field | Type | Required | Description |
|---|---|---|---|
| `label` | string | ✅ | Human-readable owner name, e.g. `Acme Corp` |
| `tier` | string | No (default `free`) | `free` · `starter` · `pro` |

**Postman setup:**

1. Set method to `POST`, URL to `http://localhost:8000/api/v1/keys`
2. **Headers** tab → add `X-Internal-Secret: <your-secret>`
3. **Body** tab → select **form-data** (not raw/JSON)
4. Add key `label` = `My Test Key`
5. Optionally add key `tier` = `pro`
6. Send

> ⚠️ Common mistake: sending the body as **raw JSON** causes a `422 Field required` error because FastAPI's `Form(...)` only reads `multipart/form-data` or `application/x-www-form-urlencoded`, never `application/json`.

**Response `201`:**

```json
{
  "id": 1,
  "label": "My Test Key",
  "tier": "free",
  "key_prefix": "dk_live_XXXXXXX",
  "api_key": "dk_live_<full-plaintext-key>",
  "created_at": "2025-01-01T00:00:00+00:00",
  "warning": "Store this key immediately. It will not be shown again."
}
```

---

### `POST /api/v1/clean` — Clean a file

**Auth required:** `Authorization: Bearer dk_live_...`

**Body:** `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | file | ✅ | `.csv` or `.xlsx` |
| `config` | string (JSON) | No | Cleaning rule map (see below) |

**Headers:**

| Header | Description |
|---|---|
| `Authorization` | `Bearer dk_live_<key>` — required |
| `X-Clean-Config` | JSON config — overrides `config` form field if both are present |
| `X-Webhook-URL` | If set, returns `202` immediately and POSTs cleaned data to this URL |

**Config shape:**

```json
{
  "columns": {
    "phone_number": ["PHONE"],
    "full_name":    ["NAME"],
    "date_of_birth":["DATE"]
  },
  "output_format": "csv"
}
```

Columns not listed receive `PASS_THROUGH` (whitespace-stripped, value preserved).

**Cleaning rules:**

| Rule | Effect |
|---|---|
| `PHONE` | Normalises Kenyan phone variants → `2547XXXXXXXX` |
| `NAME` | `.strip().title()` |
| `DATE` | Parses common date formats → `YYYY-MM-DD` |
| `strip` | Remove leading/trailing whitespace |
| `lowercase` / `uppercase` / `title_case` | Case transforms |
| `to_int` / `to_float` | Type coercion; null on failure |
| `drop_empty` | Removes the entire row if this cell is blank |
| `fill_mean` / `fill_median` | Null imputation using column stats |
| `fill_value:X` | Replace null with literal `X` |
| `clamp:lo:hi` | Numeric range clip |
| `regex:PATTERN:REPLACEMENT` | `re.sub` on the cell value |

**Responses:**

| Status | Meaning |
|---|---|
| `200` | Cleaned file returned directly (CSV or JSON) |
| `202` | Webhook mode — job queued, payload will be POSTed to `X-Webhook-URL` |
| `401` | Missing or invalid API key |
| `415` | File type not supported (only `.csv` / `.xlsx`) |
| `422` | Config JSON is malformed, or a required form field is absent |

---

### `PATCH /api/v1/keys/{key_id}/deactivate` — Deactivate a key

**Auth required:** `X-Internal-Secret` header.

Immediately blocks the key; does not delete the row.

---

### `GET /health` and `GET /api/v1/health`

Liveness probes. No auth required.

```json
{ "status": "ok", "version": "1.0.0", "docs": "/docs" }
```

---

## Error reference

| Code | `error.code` | Cause & fix |
|---|---|---|
| `401` | `INVALID_API_KEY` | No `Authorization` header, wrong prefix, or key deactivated. Check the key starts with `dk_live_` and is active in the DB. |
| `403` | `FORBIDDEN` | `X-Internal-Secret` header is wrong or missing on an admin endpoint. |
| `422` | *(FastAPI validation)* | `label` (or another `Form` field) was not sent as form-data. Switch Postman Body type to **form-data**, not raw JSON. |
| `503` | — | `TENANT_DATABASE_URL` or `INTERNAL_SERVICE_SECRET` not set in environment. |

---

## UI sandbox (`index.html`)

Open `index.html` in a browser. The API base URL defaults to `http://localhost:8000/api/v1/clean`.

1. Enter your `dk_live_...` key in the **API Key** field (required).
2. Enter an `X-Webhook-URL` to receive the cleaned payload.
3. Upload a `.csv` or `.xlsx` file.
4. Map each detected column to a cleaning rule.
5. Click **Process & Stream Data**.

Error messages from the API are automatically unwrapped and displayed in plain English — including FastAPI validation errors and structured `{ error: { code, message } }` responses.

---

## Database schema

Auto-created on first startup:

```sql
CREATE TABLE api_keys (
    id            BIGSERIAL PRIMARY KEY,
    label         TEXT        NOT NULL,
    key_hash      TEXT        NOT NULL UNIQUE,  -- SHA-256; plaintext never stored
    key_prefix    TEXT        NOT NULL,          -- first 16 chars, safe to display
    tier          TEXT        NOT NULL DEFAULT 'free'
                              CHECK (tier IN ('free', 'starter', 'pro')),
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ
);
```

---

## Project layout

```
main.py        API server — single file, all logic
index.html     Browser sandbox UI
.env.example   Environment variable template
README.md      This file
```