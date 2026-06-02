# Deploying Dodman · Data Cleaning Proxy to Render

## Prerequisites
- A [Render](https://render.com) account
- Your code pushed to a GitHub repo under `dodman-group-hq`
- A [Neon](https://neon.tech) PostgreSQL database already provisioned
- `INTERNAL_SERVICE_SECRET` value generated (`python3 -c "import secrets; print(secrets.token_hex(32))"`)

---

## Step 1 — Confirm your repo structure

Render needs these files at the repo root:

```
your-repo/
├── main.py
├── Dockerfile
└── requirements.txt
```

Push them if not already there:

```bash
git add main.py Dockerfile requirements.txt
git commit -m "feat: add Dockerfile and requirements for Render deploy"
git push origin main
```

---

## Step 2 — Create a new Web Service on Render

1. Go to [dashboard.render.com](https://dashboard.render.com) → **New** → **Web Service**
2. Connect your GitHub account and select the `dodman-group-hq` repo
3. Configure the service:

| Field | Value |
|---|---|
| **Name** | `dodman-clean-proxy` |
| **Region** | Frankfurt EU (closest to your Kenya + Europe users) |
| **Branch** | `main` |
| **Runtime** | **Docker** |
| **Dockerfile Path** | `./Dockerfile` |
| **Instance Type** | Starter ($7/mo) to start — upgrade when load demands it |
| **Auto-Deploy** | Yes (deploys on every push to `main`) |

Leave **Health Check Path** as `/health` — this matches your root liveness probe.

---

## Step 3 — Set environment variables

In the Render dashboard → your service → **Environment** tab, add these:

| Key | Value | Notes |
|---|---|---|
| `TENANT_DATABASE_URL` | `postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require` | From your Neon dashboard → Connection string → **asyncpg** format |
| `INTERNAL_SERVICE_SECRET` | `<your-generated-hex>` | Keep this secret — it gates key issuance |
| `RATE_LIMIT_FREE` | `60/hour` | Adjust without redeploying |
| `RATE_LIMIT_STARTER` | `500/hour` | Adjust without redeploying |

> **Neon URL format for asyncpg:** Replace `postgresql://` with `postgresql://` and ensure you have `?sslmode=require` at the end. Neon connection strings from the dashboard work directly — just copy the **asyncpg** variant.

---

## Step 4 — Deploy

Click **Create Web Service**. Render will:

1. Pull your repo
2. Build the Docker image (2–4 minutes first time)
3. Start the container
4. Run your `/health` probe — turns green when it responds 200

Your API will be live at:
```
https://dodman-clean-proxy.onrender.com
```

---

## Step 5 — Issue your first API key

Once deployed, run this from your terminal (or from God-Key):

```bash
# Generate a starter key for your first client
curl -X POST https://dodman-clean-proxy.onrender.com/api/v1/keys \
  -H "Content-Type: application/json" \
  -H "X-Internal-Secret: YOUR_INTERNAL_SERVICE_SECRET" \
  -d '{"label": "Acme Corp", "tier": "starter"}'
```

**Save the `api_key` value from the response immediately — it is shown only once.**

Response:
```json
{
  "id": 1,
  "label": "Acme Corp",
  "tier": "starter",
  "key_prefix": "dk_live_XXXXXXX",
  "api_key": "dk_live_<full-key-here>",
  "created_at": "2025-01-01T12:00:00Z",
  "warning": "Store this key immediately. It will not be shown again."
}
```

---

## Step 6 — Test a clean request

```bash
curl -X POST https://dodman-clean-proxy.onrender.com/api/v1/clean \
  -H "Authorization: Bearer dk_live_<your-key>" \
  -H "X-Webhook-URL: https://your-server.com/webhook" \
  -F "file=@sample.csv" \
  -F 'config={"columns":{"name":["NAME"],"phone":["PHONE"]},"output_format":"json"}'
```

Expected response:
```json
{ "status": "queued", "rows_processed": 42 }
```

---

## Postman setup

| Field | Value |
|---|---|
| Method | `POST` |
| URL | `https://dodman-clean-proxy.onrender.com/api/v1/keys` |
| Auth tab | Type: **Bearer Token**, Token: `dk_live_...` |
| Body tab | **raw → JSON** for key management; **form-data** for `/clean` with file upload |

For `/api/v1/keys` with Postman:
- **Headers:** `X-Internal-Secret: your-secret`
- **Body:** raw JSON `{"label": "Client Name", "tier": "free"}`

---

## Useful URLs once live

| URL | Purpose |
|---|---|
| `GET /health` | Render health check (load balancer probe) |
| `GET /api/v1/health` | Versioned liveness check |
| `GET /docs` | Swagger UI — interactive API explorer |
| `GET /redoc` | ReDoc — clean readable documentation |
| `GET /openapi.json` | Raw OpenAPI schema for SDK generation |

---

## Rate limit environment variables (no redeploy needed)

Change these in Render's **Environment** tab and click **Save** — the service restarts automatically:

```
RATE_LIMIT_FREE=100/hour       # was 60/hour
RATE_LIMIT_STARTER=1000/hour   # was 500/hour
```

Valid period units: `second`, `minute`, `hour`, `day`

---

## Updating the deployment

```bash
git push origin main
```

Render auto-deploys on push if **Auto-Deploy** is enabled. Zero-downtime rolling restart.

To force a manual redeploy: Render dashboard → your service → **Manual Deploy** → **Deploy latest commit**.