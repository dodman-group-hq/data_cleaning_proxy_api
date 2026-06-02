"""
Data Cleaning Proxy API
-----------------------
Stateless, single-file FastAPI service that accepts a .csv or .xlsx upload
and applies column-level cleaning rules defined in a JSON config.

Config shape (passed as header X-Clean-Config or form field `config`):
{
  "columns": {
    "email":  ["lowercase", "strip", "drop_empty"],
    "age":    ["to_int",   "clamp:0:120"],
    "name":   ["strip",    "title_case"],
    "score":  ["to_float", "fill_mean"]
  },
  "output_format": "csv"   // "csv" | "json"  (default: csv)
}

Supported rules (applied left-to-right per cell):
  strip        – remove leading/trailing whitespace
  lowercase    – .lower()
  uppercase    – .upper()
  title_case   – .title()
  drop_empty   – mark blank/null cells; rows where ANY drop_empty column is
                 empty are removed after per-cell passes
  to_int       – coerce to int, null on failure
  to_float     – coerce to float, null on failure
  fill_mean    – replace nulls with column mean  (numeric columns only)
  fill_median  – replace nulls with column median
  fill_value:X – replace nulls with literal X
  clamp:lo:hi  – numeric clamp  (lo/hi may be empty to skip one bound)
  regex:PAT:REPL – re.sub(PAT, REPL, value)
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import logging
import math
import os
import re
import secrets
import statistics
from typing import Any
from dotenv import load_dotenv

import asyncpg
import httpx
import openpyxl
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, File, Form, Header, HTTPException, Request, Security, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request as StarletteRequest

log = logging.getLogger(__name__)

# Load the .env file explicitly
load_dotenv()
# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Dodman · Data Cleaning Proxy",
    description=(
        "Stateless in-memory CSV/XLSX cleaner driven by a JSON rule config.\n\n"
        "**Interactive docs:** `/docs` (Swagger UI) · `/redoc` (ReDoc)"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Allow requests from any origin — covers browsers opening index.html via
# file://, localhost, or any custom dev port without triggering CORS preflight
# blocks.  Tighten allow_origins to specific domains in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
# The identifier function keys rate limits off the API key (from the
# Authorization header) when present, falling back to client IP.  This means
# each customer's quota is tracked independently — one customer flooding the
# API doesn't eat into another's limit.


def _rate_limit_identifier(request: StarletteRequest) -> str:
    """Return the API key token if present, else the client IP."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_identifier, default_limits=[])
app.state.limiter = limiter


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a clean, uniform 429 — never expose slowapi internals."""
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code":    "RATE_LIMIT_EXCEEDED",
                "message": "Rate limit exceeded. Please upgrade your tier or slow down.",
                "limit":   str(exc.detail),
            }
        },
        headers={"Retry-After": "60"},
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Replace FastAPI's default 422 response with a consistent error envelope.
    Surfaces the first meaningful error clearly instead of dumping raw Pydantic
    internals at the caller.
    """
    errors = exc.errors()
    first  = errors[0] if errors else {}

    # Build a human-readable field path: ["body", "label"] → "body.label"
    loc  = " → ".join(str(p) for p in first.get("loc", []))
    msg  = first.get("msg", "Validation error")
    kind = first.get("type", "unknown")

    # Give actionable hints for the most common mistakes
    hints: dict[str, str] = {
        "missing":        f"'{loc}' is required but was not provided.",
        "string_too_short": f"'{loc}' is too short.",
        "value_error":    f"'{loc}' has an invalid value: {msg}.",
    }
    human = hints.get(kind, f"'{loc}': {msg}")

    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code":    "VALIDATION_ERROR",
                "message": human,
                "fields":  [
                    {
                        "field":   " → ".join(str(p) for p in e.get("loc", [])),
                        "issue":   e.get("msg", ""),
                        "type":    e.get("type", ""),
                    }
                    for e in errors
                ],
            }
        },
    )


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Normalise all HTTPExceptions that don't already use the error envelope.
    Ensures every error response — from any part of the stack — has the same shape.
    """
    detail = exc.detail

    # Already in envelope format — pass through untouched
    if isinstance(detail, dict) and "error" in detail:
        return JSONResponse(
            status_code=exc.status_code,
            content=detail,
            headers=getattr(exc, "headers", None) or {},
        )

    # Plain string or anything else — wrap it
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code":    _status_to_code(exc.status_code),
                "message": detail if isinstance(detail, str) else str(detail),
            }
        },
        headers=getattr(exc, "headers", None) or {},
    )


def _status_to_code(status: int) -> str:
    return {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }.get(status, f"HTTP_{status}")

# ---------------------------------------------------------------------------
# Versioned router
# ---------------------------------------------------------------------------
# Routes are defined on this router and mounted by the app under a versioned
# prefix (e.g. /api/v1).  To add a v2, create a new router in a separate
# module and call app.include_router(v2_router, prefix="/api/v2").

router = APIRouter(prefix="/api/v1", tags=["v1"])

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Row = dict[str, Any]
Sheet = list[Row]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Loaded from environment — set these in your Render dashboard or .env file.
# TENANT_DATABASE_URL : asyncpg-compatible Neon connection string
# INTERNAL_SERVICE_SECRET : shared secret that protects key-management endpoints
# Required at startup; the app will not start if they are absent.

TENANT_DATABASE_URL     = os.getenv("TENANT_DATABASE_URL", "")
INTERNAL_SERVICE_SECRET = os.getenv("INTERNAL_SERVICE_SECRET", "")

# ---------------------------------------------------------------------------
# Rate limit configuration
# ---------------------------------------------------------------------------
# Adjust these via environment variables — no code changes needed.
# Format: "<count>/<period>"  where period = second | minute | hour | day
#
# Tier mapping (enforced in the identifier function below):
#   free    → RATE_LIMIT_FREE    default: 60 requests/hour
#   starter → RATE_LIMIT_STARTER default: 500 requests/hour
#   pro     → no rate limiting applied
#
# Set RATE_LIMIT_FREE=100/hour in Render to change it without a deploy.

RATE_LIMIT_FREE    = os.getenv("RATE_LIMIT_FREE",    "60/hour")
RATE_LIMIT_STARTER = os.getenv("RATE_LIMIT_STARTER", "500/hour")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "60/hour")   # fallback

# ---------------------------------------------------------------------------
# Database — connection pool (initialised on startup, torn down on shutdown)
# ---------------------------------------------------------------------------

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    """Return the live connection pool, raising clearly if it is unavailable."""
    if _pool is None:
        raise HTTPException(
            status_code=503,
            detail="Database pool not initialised — check TENANT_DATABASE_URL.",
        )
    return _pool


@app.on_event("startup")
async def _startup() -> None:
    global _pool
    if not TENANT_DATABASE_URL:
        log.warning(
            "TENANT_DATABASE_URL not set — auth endpoints will return 503. "
            "Set the env var and restart to enable API key validation."
        )
        return
    try:
        _pool = await asyncpg.create_pool(
            TENANT_DATABASE_URL,
            min_size=1,
            max_size=5,
            command_timeout=10,
        )
        await _bootstrap_schema(_pool)
        log.info("Database pool ready. Docs: http://localhost:8000/docs")
    except Exception as exc:
        log.error("Failed to connect to database: %r", exc)


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _pool:
        await _pool.close()


# ---------------------------------------------------------------------------
# Schema bootstrap  (idempotent — safe to run on every startup)
# ---------------------------------------------------------------------------

_BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id            BIGSERIAL PRIMARY KEY,
    label         TEXT        NOT NULL,
    key_hash      TEXT        NOT NULL UNIQUE,
    key_prefix    TEXT        NOT NULL,
    tier          TEXT        NOT NULL DEFAULT 'free'
                              CHECK (tier IN ('free', 'starter', 'pro')),
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (is_active);
"""


async def _bootstrap_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(_BOOTSTRAP_SQL)
    log.info("Schema bootstrap complete.")


# ---------------------------------------------------------------------------
# API key helpers
# ---------------------------------------------------------------------------

_KEY_PREFIX = "dk_live_"
_KEY_BYTES  = 32        # 256 bits of entropy → 43-char base64url suffix


def _generate_raw_key() -> str:
    """Return a brand-new plaintext API key.  Shown to the user exactly once."""
    return _KEY_PREFIX + secrets.token_urlsafe(_KEY_BYTES)


def _hash_key(raw: str) -> str:
    """SHA-256 hex digest — what we store; never the plaintext."""
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)

# Tiers ranked lowest → highest for future capability checks
TIER_RANK = {"free": 0, "starter": 1, "pro": 2}

# ---------------------------------------------------------------------------
# Key-prefix constants
# ---------------------------------------------------------------------------
# Production keys carry full processing power but must only be used against a
# live (non-test) environment.  Test keys are silently truncated to 20 rows.
# The universal sandbox key is keyed by IP and capped at 5 requests/day.

_PREFIX_LIVE    = "dk_live_"
_PREFIX_TEST    = "dk_test_"
_SANDBOX_KEY    = "dk_sandbox_test_99"

# Environment toggle — set DODMAN_ENV=production in your hosting dashboard.
# Any value other than "production" is treated as a non-live environment.
_RUNTIME_ENV = os.getenv("DODMAN_ENV", "development").lower()

# Sandbox IP rate-limit: 5 requests per day per IP (applied to _SANDBOX_KEY only)
_SANDBOX_RATE = "5/day"

# ---------------------------------------------------------------------------
# Sandbox IP rate-limit helper
# ---------------------------------------------------------------------------
# We enforce 5 req/day per IP for dk_sandbox_test_99 without relying on any
# slowapi internal methods (_check_request_limit, etc.) that differ across
# versions.  Instead we call the public limits.storage hit() / get_expiry()
# API that slowapi itself uses internally — stable across 0.1.x → 0.2.x.
#
# Storage backend mirrors the main limiter so both share the same Redis/
# memory store.  A dedicated key namespace ("sandbox:<ip>") keeps sandbox
# counts isolated from tier-based counts.

_SANDBOX_MAX_HITS  = 5
_SANDBOX_WINDOW_S  = 86_400   # 1 day in seconds


async def _check_sandbox_ip_limit(request: StarletteRequest) -> None:
    """
    Raise RateLimitExceeded (429) if the client IP has already consumed
    _SANDBOX_MAX_HITS requests in the current 24-hour window.

    Uses the same in-memory (or Redis) storage backend that the main
    slowapi Limiter uses, via its public `_storage` attribute — which is
    stable across all released slowapi versions.
    """
    from limits import parse as _parse_limit          # bundled with slowapi
    from limits.storage import MemoryStorage           # always available

    client_ip  = get_remote_address(request)
    limit_key  = f"sandbox_ip:{client_ip}"

    # Grab the storage backend from the main limiter (already initialised).
    storage = getattr(limiter, "_storage", None)
    if storage is None:
        # Limiter not yet initialised (e.g. unit-test context) — fail open.
        return

    # limits library: parse "5/day" → RateLimitItem
    rate_item = _parse_limit(_SANDBOX_RATE)

    # hit() increments the counter and returns (remaining, reset_time).
    # It returns True if the request is allowed, False if over limit.
    # The API differs slightly between limits 2.x and 3.x so we branch.
    try:
        # limits ≥ 3.x: storage.acquire_entry(key, limit, expiry) → bool
        allowed = storage.acquire_entry(
            limit_key,
            rate_item.amount,
            rate_item.get_expiry(),
        )
    except (AttributeError, TypeError):
        try:
            # limits 2.x: storage.incr(key, expiry, amount) → int
            count = storage.incr(limit_key, rate_item.get_expiry(), 1)
            allowed = count <= rate_item.amount
        except Exception:
            # Storage API is unknown — fail open rather than break the endpoint.
            return

    if not allowed:
        raise RateLimitExceeded(
            f"{_SANDBOX_MAX_HITS} per day"
        )


class APIKeyRecord:
    """Lightweight value object returned by verify_api_key."""
    __slots__ = ("id", "label", "tier", "key_prefix", "raw_key", "is_sandbox", "is_test")

    def __init__(
        self,
        id: int,
        label: str,
        tier: str,
        key_prefix: str,
        raw_key: str = "",
        is_sandbox: bool = False,
        is_test: bool = False,
    ) -> None:
        self.id         = id
        self.label      = label
        self.tier       = tier
        self.key_prefix = key_prefix
        self.raw_key    = raw_key
        self.is_sandbox = is_sandbox
        self.is_test    = is_test


async def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> APIKeyRecord:
    """
    FastAPI Security dependency — environment-enforced tiered key logic.

    Three key classes are recognised by their prefix (or exact value):

    dk_live_*          Production key.  Full processing power.  Rejected with
                       400 INVALID_ENVIRONMENT_KEY when the runtime environment
                       is not 'production'.

    dk_test_*          Test/sandbox key.  Always accepted.  Callers that use
                       this key have their uploaded sheet silently truncated to
                       at most 20 rows inside the endpoint.

    dk_sandbox_test_99 Universal open-sandbox key.  Rate-limited at 5 req/day
                       per client IP using a dedicated slowapi Limiter instance.
                       Truncates to 20 rows like test keys.

    All other keys are validated against the database as before (legacy
    dk_live_* keys still work for existing integrations).

    Raises 401 for missing/invalid/inactive keys.
    Raises 400 for a live key used outside a production environment.
    """
    _UNAUTH = HTTPException(
        status_code=401,
        detail={
            "error": {
                "code":    "INVALID_API_KEY",
                "message": "Missing or invalid API key. "
                           "Pass your key as: Authorization: Bearer dk_live_...",
            }
        },
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or not credentials.credentials:
        raise _UNAUTH

    raw = credentials.credentials.strip()

    # ── Universal sandbox key ────────────────────────────────────────────────
    # Handled entirely without a DB lookup.  IP-level rate limit is applied
    # here, inside the dependency, so it fires before any file processing.
    if raw == _SANDBOX_KEY:
        # Enforce per-IP rate limit via our stable storage helper.
        # _check_sandbox_ip_limit raises RateLimitExceeded (429) when the
        # caller has exceeded 5 requests in the current 24-hour window.
        await _check_sandbox_ip_limit(request)

        return APIKeyRecord(
            id=0,
            label="Sandbox",
            tier="free",
            key_prefix=_SANDBOX_KEY,
            raw_key=raw,
            is_sandbox=True,
            is_test=True,
        )

    # ── Production key (dk_live_) ────────────────────────────────────────────
    if raw.startswith(_PREFIX_LIVE):
        if _RUNTIME_ENV != "production":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "code":    "INVALID_ENVIRONMENT_KEY",
                        "message": "Mismatched environment key layout.",
                    }
                },
            )

    # ── Test key (dk_test_) — mark for truncation, skip env-check ────────────
    is_test_key = raw.startswith(_PREFIX_TEST)

    # ── DB validation for dk_live_ / dk_test_ / legacy dk_live_ keys ─────────
    hashed = _hash_key(raw)

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, label, tier, key_prefix, is_active
            FROM   api_keys
            WHERE  key_hash = $1
            LIMIT  1
            """,
            hashed,
        )

    if row is None or not row["is_active"]:
        raise _UNAUTH

    # Fire-and-forget last_used_at update — don't block the response on it
    async def _touch() -> None:
        try:
            async with (await get_pool()).acquire() as conn:
                await conn.execute(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                    row["id"],
                )
        except Exception:
            pass  # non-critical

    import asyncio
    asyncio.ensure_future(_touch())

    return APIKeyRecord(
        id=row["id"],
        label=row["label"],
        tier=row["tier"],
        key_prefix=row["key_prefix"],
        raw_key=raw,
        is_sandbox=False,
        is_test=is_test_key,
    )


# ---------------------------------------------------------------------------
# Internal admin guard  (protects key-management endpoints)
# ---------------------------------------------------------------------------

def verify_internal_secret(
    x_internal_secret: str | None = Header(default=None, alias="X-Internal-Secret"),
) -> None:
    """
    Dependency that checks the X-Internal-Secret header matches
    INTERNAL_SERVICE_SECRET.  Used to protect admin-only endpoints that
    should never be reachable by external clients.
    """
    if not INTERNAL_SERVICE_SECRET:
        raise HTTPException(
            status_code=503,
            detail="INTERNAL_SERVICE_SECRET not configured on this server.",
        )
    if not secrets.compare_digest(
        x_internal_secret or "",
        INTERNAL_SERVICE_SECRET,
    ):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "FORBIDDEN", "message": "Invalid internal secret."}},
        )


# ---------------------------------------------------------------------------
# Key-management endpoint  (internal only)
# ---------------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    label: str
    tier:  str = "free"


@router.post(
    "/keys",
    summary="Issue a new API key",
    description=(
        "**Internal endpoint** — requires `X-Internal-Secret` header.\n\n"
        "Creates a new API key, stores its SHA-256 hash, and returns the "
        "**plaintext key exactly once**.  Store it immediately — it cannot "
        "be recovered if lost."
    ),
    tags=["admin"],
    status_code=201,
)
async def create_api_key(
    request: Request,
    _: None = Depends(verify_internal_secret),
    pool: asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Accepts either JSON body or multipart/form-data — works from Postman,
    curl, and the sandbox UI without changing the Content-Type.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "BAD_REQUEST", "message": "Request body is not valid JSON."}},
            )
        label = body.get("label", "").strip()
        tier  = body.get("tier", "free").strip()
    else:
        # Fall back to form data (multipart or url-encoded)
        form  = await request.form()
        label = str(form.get("label", "")).strip()
        tier  = str(form.get("tier", "free")).strip()

    if not label:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "VALIDATION_ERROR", "message": "'label' is required. Provide the owner name, e.g. \'Acme Corp\'."}},
        )
    if tier not in TIER_RANK:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "VALIDATION_ERROR", "message": f"Invalid tier '{tier}\'. Must be one of: free, starter, pro."}},
        )

    raw    = _generate_raw_key()
    hashed = _hash_key(raw)
    prefix = raw[:16]          # "dk_live_XXXXXXX" — safe to store/display

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO api_keys (label, key_hash, key_prefix, tier)
            VALUES ($1, $2, $3, $4)
            RETURNING id, created_at
            """,
            label, hashed, prefix, tier,
        )

    log.info("API key issued: id=%s label=%r tier=%s prefix=%s", row["id"], label, tier, prefix)

    return JSONResponse(
        status_code=201,
        content={
            "id":         row["id"],
            "label":      label,
            "tier":       tier,
            "key_prefix": prefix,
            "api_key":    raw,          # plaintext — shown once, never stored
            "created_at": row["created_at"].isoformat(),
            "warning":    "Store this key immediately. It will not be shown again.",
        },
    )


@router.patch(
    "/keys/{key_id}/deactivate",
    summary="Deactivate an API key",
    description="**Internal endpoint** — requires `X-Internal-Secret` header.",
    tags=["admin"],
)
async def deactivate_api_key(
    key_id: int,
    _: None = Depends(verify_internal_secret),
    pool: asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
            key_id,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"Key id={key_id} not found.")
    log.info("API key deactivated: id=%s", key_id)
    return JSONResponse(content={"id": key_id, "is_active": False})


# ---------------------------------------------------------------------------
# Parsing helpers  (entirely in-memory – no disk I/O)
# ---------------------------------------------------------------------------


def _parse_csv(data: bytes) -> Sheet:
    text = data.decode("utf-8-sig")          # handles BOM
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _parse_xlsx(data: bytes) -> Sheet:
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(c) if c is not None else f"col_{i}" for i, c in enumerate(rows[0])]
    return [dict(zip(headers, row)) for row in rows[1:]]


def parse_file(filename: str, data: bytes) -> Sheet:
    lower = filename.lower()
    if lower.endswith(".csv"):
        return _parse_csv(data)
    if lower.endswith(".xlsx"):
        return _parse_xlsx(data)
    raise HTTPException(
        status_code=415,
        detail="Unsupported file type. Only .csv and .xlsx are accepted.",
    )


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


def _to_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Typed rule implementations
# ---------------------------------------------------------------------------

# ── PHONE ────────────────────────────────────────────────────────────────────
# Accepted Kenyan formats (input) → canonical output: 2547XXXXXXXX / 2541XXXXXXXX
#
#   07XXXXXXXX   →  2547XXXXXXXX   (10-digit local mobile)
#   01XXXXXXXX   →  2541XXXXXXXX   (10-digit local landline/special)
#   7XXXXXXXX    →  2547XXXXXXXX   (9-digit, missing leading 0)
#   1XXXXXXXX    →  2541XXXXXXXX   (9-digit, missing leading 0)
#   2547XXXXXXXX →  unchanged       (already canonical)
#   2541XXXXXXXX →  unchanged
#   anything else → None

_KE_PHONE_RE = re.compile(r"^254[71]\d{8}$")


def clean_phone_ke(value: Any) -> str | None:
    """Normalise a Kenyan phone number to E.164-style 254XXXXXXXXX (12 digits)."""
    if value is None:
        return None

    # Accept integer inputs (e.g. from Excel numeric cells)
    raw = str(int(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else str(value)

    # Strip every non-digit character (spaces, dashes, plus, parentheses, etc.)
    digits = re.sub(r"\D", "", raw)

    if not digits:
        return None

    # Normalise leading country-code variants
    if digits.startswith("0") and len(digits) == 10:
        # 07XXXXXXXX or 01XXXXXXXX
        digits = "254" + digits[1:]
    elif len(digits) == 9 and digits[0] in ("7", "1"):
        # 7XXXXXXXX or 1XXXXXXXX — missing leading zero
        digits = "254" + digits
    elif digits.startswith("254") and len(digits) == 12:
        pass  # already canonical — validate below
    else:
        return None  # unrecognised format

    # Final validation: must be 2547XXXXXXXX or 2541XXXXXXXX (12 digits total)
    if _KE_PHONE_RE.match(digits):
        return digits
    return None


# ── NAME ─────────────────────────────────────────────────────────────────────

def clean_name(value: Any) -> str | None:
    """Strip surrounding whitespace and apply title-case."""
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned.title() if cleaned else None


# ── DATE ─────────────────────────────────────────────────────────────────────

# Excel date serial epoch (Windows 1900 date system, accounting for the
# erroneous 1900 leap-year bug that Excel perpetuates).
_EXCEL_EPOCH = datetime.date(1899, 12, 30)

# String formats tried in order before falling back to dateutil
_DATE_FORMATS = [
    "%Y-%m-%d",    # ISO already
    "%d/%m/%Y",    # DD/MM/YYYY  (common in Kenya / UK)
    "%m/%d/%Y",    # MM/DD/YYYY  (US)
    "%d-%m-%Y",    # DD-MM-YYYY
    "%d.%m.%Y",    # DD.MM.YYYY
    "%Y/%m/%d",    # YYYY/MM/DD
    "%d %b %Y",    # 01 Jan 2024
    "%d %B %Y",    # 01 January 2024
    "%b %d, %Y",   # Jan 01, 2024
    "%B %d, %Y",   # January 01, 2024
]


def clean_date(value: Any) -> str | None:
    """Parse a date value and return it as an ISO-8601 string (YYYY-MM-DD), or None."""
    if value is None:
        return None

    # ── Already a Python date/datetime (openpyxl returns these for date cells) ─
    if isinstance(value, datetime.datetime):
        return value.date().isoformat()
    if isinstance(value, datetime.date):
        return value.isoformat()

    # ── Excel date serial number (integer or float like 45000.0) ─────────────
    raw_str = str(value).strip()
    if re.match(r"^\d{1,6}(\.\d+)?$", raw_str):
        try:
            serial = int(float(raw_str))
            # Plausible Excel serial range: 1 (1900-01-01) – 2958465 (9999-12-31)
            if 1 <= serial <= 2958465:
                parsed = _EXCEL_EPOCH + datetime.timedelta(days=serial)
                # Sanity-check: reject implausibly old dates (< 1900) returned by
                # very small serials that are more likely plain integers.
                if parsed.year >= 1900:
                    return parsed.isoformat()
        except (ValueError, OverflowError):
            pass

    # ── String formats ────────────────────────────────────────────────────────
    for fmt in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(raw_str, fmt).date().isoformat()
        except ValueError:
            continue

    # Unrecognised — return None rather than corrupt data
    return None


# ---------------------------------------------------------------------------
# Typed-rule dispatcher  +  PASS_THROUGH fallback
# ---------------------------------------------------------------------------

_TYPED_RULES = {"PHONE", "NAME", "DATE"}


def apply_typed_rule(rule: str, value: Any) -> Any:
    """
    Dispatch one of the three semantic rules.  Returns the cleaned value, or
    None when the input cannot be normalised to the expected format.
    """
    if rule == "PHONE":
        return clean_phone_ke(value)
    if rule == "NAME":
        return clean_name(value)
    if rule == "DATE":
        return clean_date(value)
    # Fallback: delegate to the legacy per-token engine
    return apply_rule(rule, value)


def process_row(row: Row, column_rules: dict[str, list[str]]) -> Row:
    """
    Apply cleaning rules to every field in *row*.

    • Columns present in *column_rules* are processed through their rule list
      (typed rules take precedence; legacy rules are applied token-by-token).
    • Columns NOT in *column_rules* receive PASS_THROUGH treatment:
      convert to str and strip — value is otherwise left untouched.
    """
    out: Row = {}
    for col, value in row.items():
        rules = column_rules.get(col)
        if rules is None:
            # PASS_THROUGH: coerce to str, strip whitespace, preserve value
            out[col] = str(value).strip() if value is not None else value
        else:
            current = value
            for rule in rules:
                if rule in _TYPED_RULES:
                    current = apply_typed_rule(rule, current)
                    # Typed rules are terminal within their semantic domain;
                    # subsequent rules still run (e.g. a drop_empty after PHONE).
                else:
                    current = apply_rule(rule, current)
            out[col] = current
    return out


def apply_rule(rule: str, value: Any) -> Any:
    """Apply a single rule token to a scalar value."""
    if rule == "strip":
        return str(value).strip() if value is not None else value
    if rule == "lowercase":
        return str(value).lower() if value is not None else value
    if rule == "uppercase":
        return str(value).upper() if value is not None else value
    if rule == "title_case":
        return str(value).title() if value is not None else value
    if rule == "to_int":
        n = _to_number(value)
        return int(n) if n is not None else None
    if rule == "to_float":
        return _to_number(value)
    if rule == "drop_empty":
        # Sentinel – handled at sheet level; return value unchanged here
        return value
    if rule.startswith("fill_value:"):
        fill = rule.split(":", 1)[1]
        return fill if (value is None or str(value).strip() == "") else value
    if rule.startswith("clamp:"):
        parts = rule.split(":")
        lo = _to_number(parts[1]) if len(parts) > 1 and parts[1] != "" else None
        hi = _to_number(parts[2]) if len(parts) > 2 and parts[2] != "" else None
        n = _to_number(value)
        if n is None:
            return value
        if lo is not None:
            n = max(lo, n)
        if hi is not None:
            n = min(hi, n)
        return n
    if rule.startswith("regex:"):
        _, pattern, replacement = rule.split(":", 2)
        return re.sub(pattern, replacement, str(value)) if value is not None else value
    # Unknown rules are ignored gracefully
    return value


def _column_numerics(sheet: Sheet, col: str) -> list[float]:
    return [
        float(row[col])
        for row in sheet
        if col in row and row[col] is not None and _to_number(row[col]) is not None
    ]


def apply_fill_stat(sheet: Sheet, col: str, stat: str) -> Sheet:
    nums = _column_numerics(sheet, col)
    if not nums:
        return sheet
    if stat == "fill_mean":
        fill = statistics.mean(nums)
    elif stat == "fill_median":
        fill = statistics.median(nums)
    else:
        return sheet
    for row in sheet:
        v = row.get(col)
        if v is None or str(v).strip() == "":
            row[col] = fill
    return sheet


def clean_sheet(sheet: Sheet, column_rules: dict[str, list[str]]) -> Sheet:
    """Apply all rules to every row; return the cleaned sheet."""

    # ── Pass 1: per-cell rules (skip stat-fills, handled in pass 2) ──────────
    stat_rules = {"fill_mean", "fill_median"}

    # Build a view of column_rules that excludes deferred stat-fill tokens so
    # process_row does not run them prematurely.  PASS_THROUGH columns (those
    # absent from column_rules) are handled inside process_row automatically.
    rules_pass1: dict[str, list[str]] = {
        col: [r for r in rules if r not in stat_rules]
        for col, rules in column_rules.items()
    }
    sheet = [process_row(row, rules_pass1) for row in sheet]

    # ── Pass 2: column-level stat fills ──────────────────────────────────────
    for col, rules in column_rules.items():
        for rule in rules:
            if rule in stat_rules:
                sheet = apply_fill_stat(sheet, col, rule)

    # ── Pass 3: drop rows where a drop_empty column is blank/null ────────────
    drop_cols = {
        col for col, rules in column_rules.items() if "drop_empty" in rules
    }
    if drop_cols:
        sheet = [
            row for row in sheet
            if not any(
                col in row and (row[col] is None or str(row[col]).strip() == "")
                for col in drop_cols
            )
        ]

    return sheet


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------


def _to_csv_bytes(sheet: Sheet) -> bytes:
    if not sheet:
        return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(sheet[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(sheet)
    return buf.getvalue().encode()


def _sanitise_for_json(sheet: Sheet) -> Sheet:
    """Replace non-finite floats so json.dumps doesn't choke."""
    clean = []
    for row in sheet:
        clean.append(
            {
                k: (None if isinstance(v, float) and (math.isnan(v) or math.isinf(v)) else v)
                for k, v in row.items()
            }
        )
    return clean


# ---------------------------------------------------------------------------
# Config resolution  (header takes precedence over form field)
# ---------------------------------------------------------------------------


def resolve_config(
    header_config: str | None,
    form_config: str | None,
) -> dict:
    raw = header_config or form_config
    if not raw:
        return {"columns": {}, "output_format": "csv"}
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON config: {exc}") from exc
    cfg.setdefault("columns", {})
    cfg.setdefault("output_format", "csv")
    return cfg


# ---------------------------------------------------------------------------
# Webhook dispatcher  (runs in background after 202 is returned to client)
# ---------------------------------------------------------------------------


async def _dispatch_webhook(url: str, payload: list[Row]) -> None:
    """
    POST the cleaned JSON payload to *url* using a dedicated async client.

    Failures are logged but never re-raised — the caller (our API container)
    must not crash because a client's destination server is unreachable.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            log.info(
                "Webhook delivered: url=%s status=%s rows=%d",
                url,
                response.status_code,
                len(payload),
            )
    except httpx.TimeoutException:
        log.error("Webhook timed out: url=%s", url)
    except httpx.HTTPStatusError as exc:
        log.error(
            "Webhook rejected by destination: url=%s status=%s body=%.200s",
            url,
            exc.response.status_code,
            exc.response.text,
        )
    except httpx.RequestError as exc:
        # Covers connection refused, DNS failure, SSL errors, etc.
        log.error("Webhook request error: url=%s error=%r", url, exc)
    except Exception as exc:  # noqa: BLE001 – intentional catch-all
        log.exception("Unexpected error dispatching webhook: url=%s error=%r", url, exc)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def _resolve_tier_limit(request: StarletteRequest) -> str:
    """
    Return the rate limit string for the current request.

    slowapi calls this before the endpoint body runs, so we read the tier
    directly from the Authorization header and resolve it against the tier
    map — the same token the auth dependency will validate moments later.

    This means the limit is applied per-API-key (keyed by the token in
    _rate_limit_identifier), and the string reflects the caller's tier.
    Unauthenticated requests get the free-tier limit; they will still fail
    at the auth dependency.
    """
    auth  = request.headers.get("Authorization", "")
    # We don't have the resolved tier yet at this point — read it from state
    # if auth has already run (e.g. on retry), else default to free.
    tier  = getattr(request.state, "api_key_tier", "free")
    return {
        "free":    RATE_LIMIT_FREE,
        "starter": RATE_LIMIT_STARTER,
        "pro":     "99999/hour",    # effectively unlimited — pro pays for throughput
    }.get(tier, RATE_LIMIT_DEFAULT)


@router.post(
    "/clean",
    summary="Upload and clean a CSV or XLSX file",
    responses={
        200: {"description": "Cleaned file streamed synchronously (CSV or JSON) — no X-Webhook-URL supplied"},
        202: {"description": "Processing queued; cleaned payload will be POSTed to X-Webhook-URL"},
        400: {"description": "Live key used in a non-production environment"},
        415: {"description": "Unsupported file type"},
        422: {"description": "Validation / config error"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit(RATE_LIMIT_DEFAULT, key_func=_rate_limit_identifier)
async def clean_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description=".csv or .xlsx file to clean"),
    config: str | None = Form(
        default=None,
        description="JSON cleaning config (overridden by X-Clean-Config header if present)",
    ),
    output_format: str | None = Form(
        default=None,
        description="'json' or 'csv' — overrides the value in the config body (default: json)",
    ),
    x_clean_config: str | None = Header(
        default=None,
        alias="X-Clean-Config",
        description="JSON cleaning config (takes precedence over form field)",
    ),
    x_webhook_url: str | None = Header(
        default=None,
        alias="X-Webhook-URL",
        description=(
            "Optional. When present, the endpoint returns 202 immediately and "
            "POSTs the cleaned JSON array to this URL asynchronously in the "
            "background.  When absent, the cleaned file is streamed back "
            "directly in the HTTP response as a browser download."
        ),
    ),
    x_output_format: str | None = Header(
        default=None,
        alias="X-Output-Format",
        description="'json' or 'csv' — header alternative to the output_format form field",
    ),
    api_key: APIKeyRecord = Security(verify_api_key),
):
    # ── Store tier on request state so the rate limiter can read it ─────────
    request.state.api_key_tier = api_key.tier

    # ── Sandbox IP rate limit (dk_sandbox_test_99) ───────────────────────────
    # Already enforced inside verify_api_key via _check_sandbox_ip_limit.
    # The dependency runs first and raises 429 before we reach this point,
    # so no second check is needed here.

    # ── Read file bytes in-memory ─────────────────────────────────────────────
    raw = await file.read()

    # ── Parse ─────────────────────────────────────────────────────────────────
    sheet = parse_file(file.filename or "", raw)

    # ── Row truncation: dk_test_* and dk_sandbox_test_99 cap at 20 rows ──────
    # Rows 21+ are silently dropped before any cleaning is applied.
    _SANDBOX_ROW_LIMIT = 20
    truncated = False
    original_row_count = len(sheet)
    if api_key.is_test and len(sheet) > _SANDBOX_ROW_LIMIT:
        sheet = sheet[:_SANDBOX_ROW_LIMIT]
        truncated = True
        log.info(
            "Row truncation applied: original=%d truncated_to=%d key_prefix=%s",
            original_row_count, _SANDBOX_ROW_LIMIT, api_key.key_prefix,
        )

    # ── Config ────────────────────────────────────────────────────────────────
    cfg = resolve_config(x_clean_config, config)
    column_rules: dict[str, list[str]] = cfg["columns"]

    # Resolve output_format: form param > header > config body > default json.
    # The form `output_format` field and the X-Output-Format header both
    # override whatever is in the JSON config body.
    resolved_format: str = (
        (output_format or x_output_format or cfg.get("output_format", "json"))
        .strip()
        .lower()
    )
    if resolved_format not in {"json", "csv"}:
        resolved_format = "json"

    # ── Clean ─────────────────────────────────────────────────────────────────
    cleaned   = clean_sheet(sheet, column_rules)
    sanitised = _sanitise_for_json(cleaned)

    # ── Webhook mode: enqueue background dispatch → return 202 immediately ────
    if x_webhook_url:
        background_tasks.add_task(_dispatch_webhook, x_webhook_url, sanitised)
        log.info(
            "Job queued: rows=%d webhook=%s key=%s tier=%s truncated=%s",
            len(sanitised), x_webhook_url, api_key.key_prefix, api_key.tier, truncated,
        )
        return JSONResponse(
            status_code=202,
            content={
                "status":        "queued",
                "rows_processed": len(sanitised),
                **({"rows_dropped": original_row_count - _SANDBOX_ROW_LIMIT} if truncated else {}),
            },
        )

    # ── Direct streaming mode: compile in-memory buffer → StreamingResponse ───
    # No webhook URL was provided.  Build the output entirely in an io.StringIO
    # buffer and stream it back with a Content-Disposition header so the browser
    # treats it as a file download.

    if resolved_format == "csv":
        buf = io.StringIO()
        if sanitised:
            writer = csv.DictWriter(
                buf,
                fieldnames=list(sanitised[0].keys()),
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(sanitised)
        payload      = buf.getvalue().encode("utf-8")
        media_type   = "text/csv"
        disposition  = "attachment; filename=cleaned_file.csv"
    else:
        payload      = json.dumps(sanitised, ensure_ascii=False, indent=2).encode("utf-8")
        media_type   = "application/json"
        disposition  = "attachment; filename=cleaned_file.json"

    log.info(
        "Streaming response: format=%s rows=%d size_bytes=%d key=%s truncated=%s",
        resolved_format, len(sanitised), len(payload), api_key.key_prefix, truncated,
    )

    extra_headers: dict[str, str] = {}
    if truncated:
        extra_headers["X-Rows-Truncated"] = str(original_row_count - _SANDBOX_ROW_LIMIT)

    return StreamingResponse(
        io.BytesIO(payload),
        status_code=200,
        media_type=media_type,
        headers={"Content-Disposition": disposition, **extra_headers},
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health", include_in_schema=False)
async def health():
    """Root-level liveness probe (load balancers, Render health checks)."""
    return {"status": "ok"}


@router.get("/health", include_in_schema=True, summary="API v1 liveness probe")
async def health_v1():
    """Versioned liveness probe — confirms the v1 router is mounted."""
    return {"status": "ok", "version": "1.0.0", "docs": "/docs"}


# ---------------------------------------------------------------------------
# Mount versioned router
# ---------------------------------------------------------------------------
# Add future versions here:
#   from routers import v2
#   app.include_router(v2.router, prefix="/api/v2")

app.include_router(router)