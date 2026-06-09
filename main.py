"""
Dodman · Data Cleaning Proxy API  v2.0
---------------------------------------
Stateless, single-file FastAPI service — cleaned rows returned directly or
routed to a webhook.  Now includes:

  • Unified asyncpg schema (users / api_keys / billing_ledger)
  • dk_test_ / dk_live_ prefix enforcement with environment mismatch guard
  • Per-request billing telemetry (perf_counter → billing_ledger via BackgroundTasks)
  • request_id middleware + global error envelope on every response
  • Cookie-based auth (signup / login / logout) with passlib bcrypt
  • Dashboard route serving a Jinja2 HTML template

Env vars (set in .env or hosting dashboard):
  TENANT_DATABASE_URL       asyncpg-compatible Neon/Postgres connection string
  INTERNAL_SERVICE_SECRET   Shared secret for admin-only endpoints
  SESSION_SECRET_KEY        Secret for signing session cookies (min 32 chars)
  DODMAN_ENV                "production" enables sk_live_ keys  (default: development)
  RATE_LIMIT_FREE           default 60/hour
  RATE_LIMIT_STARTER        default 500/hour
"""

from __future__ import annotations

import asyncio
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
import time
import uuid
from typing import Any, Callable

from charset_normalizer import from_bytes as _detect_encoding
import phonenumbers

import asyncpg
import httpx
import openpyxl
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from dotenv import load_dotenv
from fastapi import (
    APIRouter, BackgroundTasks, Cookie, Depends, FastAPI,
    File, Form, Header, HTTPException, Request, Response, Security, UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

load_dotenv()
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sentinel — raised when a browser-facing route needs a login redirect.
# Caught by _login_redirect_handler below and converted to a 303 response.
# Cannot use a plain RedirectResponse here because `raise` only accepts
# BaseException subclasses, not Starlette Response objects.
# ---------------------------------------------------------------------------

class _NeedsLoginRedirect(Exception):
    """Raised by get_current_user when the caller is a browser (HTML request)."""
    pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_DATABASE_URL     = os.getenv("TENANT_DATABASE_URL", "")
INTERNAL_SERVICE_SECRET = os.getenv("INTERNAL_SERVICE_SECRET", "")
SESSION_SECRET_KEY      = os.getenv("SESSION_SECRET_KEY", secrets.token_hex(32))
# _RUNTIME_ENV is intentionally a function, not a module-level constant.
# os.getenv() (and load_dotenv) only run once at import time, so a frozen
# string would never pick up .env changes between requests.  Reading
# os.environ directly on every call means the value is always current.
def _RUNTIME_ENV() -> str:
    return os.environ.get("DODMAN_ENV", "development").strip().lower()

RATE_LIMIT_FREE     = os.getenv("RATE_LIMIT_FREE",    "60/hour")
RATE_LIMIT_STARTER  = os.getenv("RATE_LIMIT_STARTER", "500/hour")
RATE_LIMIT_DEFAULT  = os.getenv("RATE_LIMIT_DEFAULT", "60/hour")

# ---------------------------------------------------------------------------
# Paystack
# ---------------------------------------------------------------------------
PAYSTACK_SECRET_KEY       = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY       = os.getenv("PAYSTACK_PUBLIC_KEY", "")
# Plan codes from your Paystack dashboard → Subscriptions → Plans
PAYSTACK_PLAN_STARTER     = os.getenv("PAYSTACK_PLAN_STARTER", "")   # e.g. PLN_xxxx
PAYSTACK_PLAN_PRO         = os.getenv("PAYSTACK_PLAN_PRO", "")       # e.g. PLN_yyyy
# Your public deployment URL — used to build callback URLs sent to Paystack
APP_BASE_URL              = os.getenv("APP_BASE_URL", "http://localhost:8000")
# Paystack signs webhook payloads with this secret; verify before trusting
PAYSTACK_WEBHOOK_SECRET   = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# Resend (transactional email)
RESEND_API_KEY  = os.getenv("RESEND_API_KEY", "")
RESEND_FROM     = os.getenv("RESEND_FROM", "billing@dodman.group")
RESEND_API_URL  = "https://api.resend.com/emails"

# ---------------------------------------------------------------------------
# Key-prefix constants
# ---------------------------------------------------------------------------

_PREFIX_LIVE     = "dk_live_"
_PREFIX_TEST     = "dk_test_"
_SANDBOX_KEY     = "dk_sandbox_test_99"        # legacy open-sandbox key
_KEY_BYTES       = 32                           # 256 bits entropy

_SANDBOX_MAX_HITS = 5
_SANDBOX_RATE     = "5/day"

# ---------------------------------------------------------------------------
# File size caps (enforced before any parsing or compute)
# ---------------------------------------------------------------------------
# Starter: 50 MB  |  Pro: 500 MB  |  test keys: 1 MB
_MAX_FILE_BYTES_STARTER = 50  * 1024 * 1024   # 50 MB
_MAX_FILE_BYTES_PRO     = 500 * 1024 * 1024   # 500 MB
_MAX_FILE_BYTES_TEST    = 1   * 1024 * 1024   # 1 MB  (sandbox / test keys)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def _verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ---------------------------------------------------------------------------
# Session token helpers  (simple signed token — no JWT dep required)
# ---------------------------------------------------------------------------

def _make_session_token(user_id: str) -> str:
    """
    Create a tamper-evident session token:
      <user_id>:<nonce>:<hmac_hex>
    The HMAC uses SESSION_SECRET_KEY so we can validate it without a DB lookup.
    """
    import hmac as _hmac
    nonce   = secrets.token_urlsafe(16)
    payload = f"{user_id}:{nonce}"
    sig     = _hmac.new(SESSION_SECRET_KEY.encode(), payload.encode(), "sha256").hexdigest()
    return f"{payload}:{sig}"


def _decode_session_token(token: str) -> str | None:
    """Return the user_id if the token is valid, else None."""
    import hmac as _hmac
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None
        user_id, nonce, sig = parts
        payload  = f"{user_id}:{nonce}"
        expected = _hmac.new(SESSION_SECRET_KEY.encode(), payload.encode(), "sha256").hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        return user_id
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def _rate_limit_identifier(request: StarletteRequest) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_identifier, default_limits=[])

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Dodman · Data Cleaning Proxy",
    description=(
        "Stateless in-memory CSV/XLSX cleaner driven by a JSON rule config.\n\n"
        "**Interactive docs:** `/docs` · `/redoc`"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.state.limiter = limiter

# Templates — rendered for the dashboard route
templates = Jinja2Templates(directory="templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS", "PATCH", "DELETE"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ===========================================================================
# Module 3 — request_id middleware + global error envelope
# ===========================================================================

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Attach a unique request_id UUID to every incoming request so that error
    envelopes, logs, and traces share a common correlation handle.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(RequestIdMiddleware)


def _get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


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


def _error_envelope(
    code: str,
    message: str,
    request_id: str,
    extra: dict | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "error": {
            "code":       code,
            "message":    message,
            "request_id": request_id,
        }
    }
    if extra:
        payload["error"].update(extra)
    return payload


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content=_error_envelope(
            "RATE_LIMIT_EXCEEDED",
            "Rate limit exceeded. Please upgrade your tier or slow down.",
            _get_request_id(request),
            {"limit": str(exc.detail)},
        ),
        headers={"Retry-After": "60"},
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    first  = errors[0] if errors else {}
    loc    = " → ".join(str(p) for p in first.get("loc", []))
    msg    = first.get("msg", "Validation error")
    kind   = first.get("type", "unknown")
    hints: dict[str, str] = {
        "missing":          f"'{loc}' is required but was not provided.",
        "string_too_short": f"'{loc}' is too short.",
        "value_error":      f"'{loc}' has an invalid value: {msg}.",
    }
    human = hints.get(kind, f"'{loc}': {msg}")
    return JSONResponse(
        status_code=422,
        content=_error_envelope(
            "VALIDATION_FAILED",
            human,
            _get_request_id(request),
            {
                "fields": [
                    {
                        "field": " → ".join(str(p) for p in e.get("loc", [])),
                        "issue": e.get("msg", ""),
                        "type":  e.get("type", ""),
                    }
                    for e in errors
                ]
            },
        ),
    )


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail     = exc.detail
    request_id = _get_request_id(request)

    # Already fully enveloped — inject request_id and pass through
    if isinstance(detail, dict) and "error" in detail:
        detail["error"].setdefault("request_id", request_id)
        return JSONResponse(
            status_code=exc.status_code,
            content=detail,
            headers=getattr(exc, "headers", None) or {},
        )

    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(
            _status_to_code(exc.status_code),
            detail if isinstance(detail, str) else str(detail),
            request_id,
        ),
        headers=getattr(exc, "headers", None) or {},
    )


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled exception on %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content=_error_envelope(
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred. Our team has been notified.",
            _get_request_id(request),
        ),
    )


@app.exception_handler(_NeedsLoginRedirect)
async def _login_redirect_handler(request: Request, exc: _NeedsLoginRedirect) -> Response:
    """Convert the sentinel into an actual 303 redirect to the login page."""
    resp = RedirectResponse(url="/auth/login-page", status_code=303)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


# ===========================================================================
# Database — connection pool
# ===========================================================================

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise HTTPException(
            status_code=503,
            detail="Database pool not initialised — check TENANT_DATABASE_URL.",
        )
    return _pool


# ---------------------------------------------------------------------------
# Schema bootstrap  (idempotent — mirrors the SQL migration file)
# ---------------------------------------------------------------------------

_BOOTSTRAP_SQL = """
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    last_env      VARCHAR(8)   NOT NULL DEFAULT 'test'
                               CHECK (last_env IN ('test', 'live')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
-- Idempotent column add for existing deployments
DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_env VARCHAR(8) NOT NULL DEFAULT 'test'
        CHECK (last_env IN ('test', 'live'));
EXCEPTION WHEN others THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS api_keys (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID         REFERENCES users(id) ON DELETE SET NULL,
    key_hash      VARCHAR(64)  NOT NULL UNIQUE,
    key_prefix    VARCHAR(32)  NOT NULL,
    label         TEXT         NOT NULL DEFAULT '',
    environment   VARCHAR(8)   NOT NULL DEFAULT 'test'
                               CHECK (environment IN ('test', 'live')),
    tier          VARCHAR(16)  NOT NULL DEFAULT 'free'
                               CHECK (tier IN ('free', 'starter', 'pro')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user   ON api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_env    ON api_keys (environment);

CREATE TABLE IF NOT EXISTS billing_ledger (
    id          BIGSERIAL    PRIMARY KEY,
    api_key_id  UUID         REFERENCES api_keys(id) ON DELETE SET NULL,
    key_prefix  VARCHAR(32)  NOT NULL DEFAULT '',
    timestamp   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    rows_in     INT          NOT NULL DEFAULT 0,
    rows_out    INT          NOT NULL DEFAULT 0,
    file_type   VARCHAR(8)   NOT NULL DEFAULT '',
    duration_ms INT          NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ledger_api_key   ON billing_ledger (api_key_id);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON billing_ledger (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_prefix    ON billing_ledger (key_prefix);

-- ---------------------------------------------------------------------------
-- subscriptions  (one active row per user; updated by Paystack webhooks)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscriptions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Paystack identifiers
    paystack_customer_id    VARCHAR(64)  NOT NULL DEFAULT '',
    paystack_subscription_id VARCHAR(64) NOT NULL DEFAULT '',
    paystack_plan_code      VARCHAR(64)  NOT NULL DEFAULT '',

    -- Mirrored from Paystack: active | cancelled | non-renewing | attention | pending
    status              VARCHAR(20)  NOT NULL DEFAULT 'pending',

    -- Maps to your tier names: starter | pro
    plan                VARCHAR(16)  NOT NULL DEFAULT 'starter',

    -- Billing cycle dates from Paystack
    current_period_start TIMESTAMPTZ,
    current_period_end   TIMESTAMPTZ,

    -- Full Paystack event payload for debugging/auditing
    last_event_data     JSONB,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_user       ON subscriptions (user_id);
CREATE INDEX        IF NOT EXISTS idx_sub_status     ON subscriptions (status);
CREATE INDEX        IF NOT EXISTS idx_sub_paystack_id ON subscriptions (paystack_subscription_id);

-- ---------------------------------------------------------------------------
-- webhook_dead_letter  (payloads that exhausted all retry attempts)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_dead_letter (
    id           BIGSERIAL    PRIMARY KEY,
    api_key_id   UUID         REFERENCES api_keys(id) ON DELETE SET NULL,
    key_prefix   VARCHAR(32)  NOT NULL DEFAULT '',
    webhook_url  TEXT         NOT NULL,
    payload_rows INT          NOT NULL DEFAULT 0,
    attempts     INT          NOT NULL DEFAULT 0,
    last_error   TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dlq_created ON webhook_dead_letter (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dlq_key     ON webhook_dead_letter (api_key_id);

-- ---------------------------------------------------------------------------
-- password_resets  (one active token per user; expires after 1 hour)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_resets (
    id         BIGSERIAL    PRIMARY KEY,
    user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64)  NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ  NOT NULL,
    used       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pw_reset_token  ON password_resets (token_hash);
CREATE INDEX IF NOT EXISTS idx_pw_reset_user   ON password_resets (user_id);
CREATE INDEX IF NOT EXISTS idx_pw_reset_expiry ON password_resets (expires_at);

-- ---------------------------------------------------------------------------
-- clean_jobs  (async job tracking — one row per webhook-mode POST /clean)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clean_jobs (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id    UUID         REFERENCES api_keys(id) ON DELETE SET NULL,
    key_prefix    VARCHAR(32)  NOT NULL DEFAULT '',
    status        VARCHAR(16)  NOT NULL DEFAULT 'queued'
                               CHECK (status IN ('queued','processing','delivered','failed')),
    webhook_url   TEXT         NOT NULL DEFAULT '',
    rows_in       INT          NOT NULL DEFAULT 0,
    rows_out      INT          NOT NULL DEFAULT 0,
    file_type     VARCHAR(8)   NOT NULL DEFAULT '',
    duration_ms   INT          NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_jobs_api_key ON clean_jobs (api_key_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status  ON clean_jobs (status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON clean_jobs (created_at DESC);
"""


async def _bootstrap_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(_BOOTSTRAP_SQL)
    log.info("Schema bootstrap complete.")


@app.on_event("startup")
async def _startup() -> None:
    global _pool
    if not TENANT_DATABASE_URL:
        log.warning("TENANT_DATABASE_URL not set — DB features disabled.")
        return
    try:
        _pool = await asyncpg.create_pool(
            TENANT_DATABASE_URL,
            min_size=2,
            max_size=10,
            command_timeout=15,
        )
        await _bootstrap_schema(_pool)
        log.info("Database pool ready.  Docs: http://localhost:8000/docs")
    except Exception as exc:
        log.error("Failed to connect to database: %r", exc)


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _pool:
        await _pool.close()


# ===========================================================================
# Module 2 — Billing telemetry (BackgroundTask)
# ===========================================================================

async def _write_billing_ledger(
    pool:       asyncpg.Pool,
    api_key_id: str | None,
    key_prefix: str,
    rows_in:    int,
    rows_out:   int,
    file_type:  str,
    duration_ms: int,
) -> None:
    """
    Fire-and-forget ledger insert.  Called via BackgroundTasks so it never
    blocks the HTTP response.  Failures are logged but never propagated.
    """
    try:
        # api_key_id must be a UUID or NULL; sandbox keys have no DB row.
        key_uuid: Any = None
        if api_key_id:
            try:
                key_uuid = uuid.UUID(str(api_key_id))
            except ValueError:
                key_uuid = None

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO billing_ledger
                    (api_key_id, key_prefix, rows_in, rows_out, file_type, duration_ms)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                key_uuid,
                key_prefix,
                rows_in,
                rows_out,
                file_type,
                duration_ms,
            )
    except Exception:
        log.exception("billing_ledger insert failed — non-fatal")


# ===========================================================================
# Audit log writer
# ===========================================================================
# Writes to the shared audit_logs table used across all Dodman services.
# Every row carries  details->>'service' = 'data_cleaning_proxy'  so you can
# filter this service out of the shared table with a single WHERE clause:
#
#   SELECT * FROM audit_logs
#   WHERE  details->>'service' = 'data_cleaning_proxy'
#   ORDER  BY timestamp DESC;
#
# All writes are fire-and-forget via BackgroundTasks — failures are logged
# server-side but never propagate to the caller.
# ===========================================================================

_AUDIT_SERVICE = "data_cleaning_proxy"


async def _write_audit_log(
    pool:        asyncpg.Pool,
    action:      str,
    success:     bool,
    *,
    user_type:   str        = "anonymous",
    target_type: str        = "",
    target_id:   str        = "",
    ip_address:  str        = "",
    details:     dict | None = None,
) -> None:
    """
    Insert one row into audit_logs.  Called via BackgroundTasks.

    Mandatory filtering fields baked into every row:
      details->>'service'  = 'data_cleaning_proxy'
      details->>'env'      = current DODMAN_ENV value

    Args:
        action      – dot-namespaced event string, e.g. 'user.login'
        success     – True if the operation completed without error
        user_type   – 'anonymous' | 'user' | 'admin' | 'api_key'
        target_type – entity being acted on: 'user' | 'api_key' | 'file' | 'request' | 'session'
        target_id   – string identifier of that entity (UUID, key prefix, filename, …)
        ip_address  – client IP extracted from the request
        details     – arbitrary extra fields merged into the JSONB column
    """
    payload = {
        "service": _AUDIT_SERVICE,
        "env":     _RUNTIME_ENV(),
        **(details or {}),
    }
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs
                    (timestamp, user_type, action, target_type, target_id,
                     details, ip_address, success)
                VALUES
                    (NOW(), $1, $2, $3, $4, $5::jsonb, $6, $7)
                """,
                user_type,
                action,
                target_type,
                target_id,
                json.dumps(payload),
                ip_address,
                success,
            )
    except Exception:
        log.exception("audit_log write failed (non-fatal): action=%s target=%s", action, target_id)


def _client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For for proxied deployments."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


# ===========================================================================
# API key helpers
# ===========================================================================

def _generate_raw_key(environment: str) -> str:
    prefix = _PREFIX_LIVE if environment == "live" else _PREFIX_TEST
    return prefix + secrets.token_urlsafe(_KEY_BYTES)


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ===========================================================================
# Module 2 — Prefix enforcement + authentication dependency
# ===========================================================================

_bearer = HTTPBearer(auto_error=False)
TIER_RANK = {"free": 0, "starter": 1, "pro": 2}


async def _log_auth_failure(
    request:    Request,
    action:     str,
    reason:     str,
    target_id:  str = "",
) -> None:
    """
    Convenience wrapper for logging auth-layer failures.
    Safe to call even when the DB pool is unavailable — failures are silently
    swallowed so they never affect the error response being returned.
    """
    try:
        pool = await get_pool()
        await _write_audit_log(
            pool,
            action=action,
            success=False,
            user_type="anonymous",
            target_type="request",
            target_id=target_id,
            ip_address=_client_ip(request),
            details={"reason": reason, "request_id": _get_request_id(request)},
        )
    except Exception:
        pass  # pool unavailable or write failed — never block the auth error response


class APIKeyRecord:
    __slots__ = ("id", "label", "tier", "key_prefix", "environment",
                 "raw_key", "is_sandbox", "is_test", "user_id")

    def __init__(
        self,
        id:          Any,
        label:       str,
        tier:        str,
        key_prefix:  str,
        environment: str  = "test",
        raw_key:     str  = "",
        is_sandbox:  bool = False,
        is_test:     bool = False,
        user_id:     Any  = None,
    ) -> None:
        self.id          = id
        self.label       = label
        self.tier        = tier
        self.key_prefix  = key_prefix
        self.environment = environment
        self.raw_key     = raw_key
        self.is_sandbox  = is_sandbox
        self.is_test     = is_test
        self.user_id     = user_id


async def _check_sandbox_ip_limit(request: StarletteRequest) -> None:
    from limits import parse as _parse_limit

    client_ip = get_remote_address(request)
    limit_key = f"sandbox_ip:{client_ip}"
    storage   = getattr(limiter, "_storage", None)
    if storage is None:
        return
    rate_item = _parse_limit(_SANDBOX_RATE)
    try:
        allowed = storage.acquire_entry(limit_key, rate_item.amount, rate_item.get_expiry())
    except (AttributeError, TypeError):
        try:
            count   = storage.incr(limit_key, rate_item.get_expiry(), 1)
            allowed = count <= rate_item.amount
        except Exception:
            return
    if not allowed:
        raise RateLimitExceeded(f"{_SANDBOX_MAX_HITS} per day")


async def verify_api_key(
    request:     Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> APIKeyRecord:
    """
    Dependency: authenticates the Bearer token and enforces prefix/environment rules.

    dk_live_*          Live key.  Requires DODMAN_ENV=production; raises 400
                       INVALID_ENVIRONMENT_KEY if the runtime env is not live.
    dk_test_*          Test key.  Truncates upload to 20 rows; accepted everywhere.
    dk_sandbox_test_99 Universal open-sandbox key.  5 req/day per IP; 20-row cap.
    """
    _UNAUTH = HTTPException(
        status_code=401,
        detail=_error_envelope(
            "INVALID_API_KEY",
            "Missing or invalid API key. Pass your key as: Authorization: Bearer dk_test_...",
            _get_request_id(request),
        ),
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or not credentials.credentials:
        raise _UNAUTH

    raw = credentials.credentials.strip()

    # ── Universal sandbox key ─────────────────────────────────────────────────
    if raw == _SANDBOX_KEY:
        await _check_sandbox_ip_limit(request)
        return APIKeyRecord(
            id=None, label="Sandbox", tier="free",
            key_prefix=_SANDBOX_KEY, environment="test",
            raw_key=raw, is_sandbox=True, is_test=True,
        )

    # ── Prefix / environment mismatch enforcement ─────────────────────────────
    if raw.startswith(_PREFIX_LIVE):
        if _RUNTIME_ENV() != "production":
            asyncio.ensure_future(_log_auth_failure(
                request, "auth.env_mismatch",
                f"dk_live_ key used in {_RUNTIME_ENV()} environment",
                raw[:16],
            ))
            raise HTTPException(
                status_code=400,
                detail=_error_envelope(
                    "INVALID_ENVIRONMENT_KEY",
                    "Mismatched environment key layout. "
                    "A dk_live_ key cannot be used outside a production environment.",
                    _get_request_id(request),
                ),
            )
    elif raw.startswith(_PREFIX_TEST):
        # Test keys are always accepted regardless of runtime env
        pass
    else:
        # Legacy dk_live_ keys or unknown prefixes go straight to DB validation
        pass

    is_test_key = raw.startswith(_PREFIX_TEST)

    # ── DB validation ─────────────────────────────────────────────────────────
    hashed = _hash_key(raw)
    pool   = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, user_id, label, tier, key_prefix, environment, is_active
            FROM   api_keys
            WHERE  key_hash = $1
            LIMIT  1
            """,
            hashed,
        )

    if row is None or not row["is_active"]:
        asyncio.ensure_future(_log_auth_failure(
            request, "auth.invalid_key",
            "Key not found or inactive",
            raw[:16] if len(raw) >= 8 else "redacted",
        ))
        raise _UNAUTH

    # ── Secondary environment guard: key's stored environment vs request key ──
    # A key stored as environment='test' that physically has a dk_live_ prefix
    # is a data anomaly — reject it explicitly.
    stored_env = row["environment"]
    if raw.startswith(_PREFIX_LIVE) and stored_env != "live":
        asyncio.ensure_future(_log_auth_failure(
            request, "auth.env_mismatch",
            "dk_live_ prefix but key stored as test environment",
            raw[:16],
        ))
        raise HTTPException(
            status_code=400,
            detail=_error_envelope(
                "INVALID_ENVIRONMENT_KEY",
                "This dk_live_ key is registered as a test-environment key. "
                "Check your key configuration.",
                _get_request_id(request),
            ),
        )
    if raw.startswith(_PREFIX_TEST) and stored_env != "test":
        asyncio.ensure_future(_log_auth_failure(
            request, "auth.env_mismatch",
            "dk_test_ prefix but key stored as live environment",
            raw[:16],
        ))
        raise HTTPException(
            status_code=400,
            detail=_error_envelope(
                "INVALID_ENVIRONMENT_KEY",
                "This dk_test_ key is registered as a live-environment key. "
                "Check your key configuration.",
                _get_request_id(request),
            ),
        )

    # Fire-and-forget last_used_at update
    async def _touch() -> None:
        try:
            async with (await get_pool()).acquire() as conn:
                await conn.execute(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                    row["id"],
                )
        except Exception:
            pass

    asyncio.ensure_future(_touch())

    return APIKeyRecord(
        id=str(row["id"]),
        label=row["label"],
        tier=row["tier"],
        key_prefix=row["key_prefix"],
        environment=stored_env,
        raw_key=raw,
        is_sandbox=False,
        is_test=is_test_key,
        user_id=str(row["user_id"]) if row["user_id"] else None,
    )


# ===========================================================================
# Internal admin guard
# ===========================================================================

def verify_internal_secret(
    x_internal_secret: str | None = Header(default=None, alias="X-Internal-Secret"),
) -> None:
    if not INTERNAL_SERVICE_SECRET:
        raise HTTPException(status_code=503, detail="INTERNAL_SERVICE_SECRET not configured.")
    if not secrets.compare_digest(x_internal_secret or "", INTERNAL_SERVICE_SECRET):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "FORBIDDEN", "message": "Invalid internal secret."}},
        )


# ===========================================================================
# Versioned API router
# ===========================================================================

router = APIRouter(prefix="/api/v1", tags=["v1"])

Row   = dict[str, Any]
Sheet = list[Row]

# ---------------------------------------------------------------------------
# Rate-limit resolver
# ---------------------------------------------------------------------------

def _resolve_tier_limit(request: StarletteRequest) -> str:
    tier = getattr(request.state, "api_key_tier", "free")
    return {
        "free":    RATE_LIMIT_FREE,
        "starter": RATE_LIMIT_STARTER,
        "pro":     "99999/hour",
    }.get(tier, RATE_LIMIT_DEFAULT)


# ===========================================================================
# Module 4 — Auth routes (signup / login / logout)
# ===========================================================================

auth_router = APIRouter(prefix="/auth", tags=["auth"])


class SignupRequest(BaseModel):
    email:    EmailStr
    password: str


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


@auth_router.post("/signup", status_code=201, summary="Register a new user account")
async def signup(
    request: Request,
    body:    SignupRequest,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    # Normalise email
    email = body.email.lower().strip()

    if len(body.password) < 8:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "Password must be at least 8 characters.",
                _get_request_id(request),
            ),
        )

    pw_hash = _hash_password(body.password)

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (email, password_hash)
                VALUES ($1, $2)
                RETURNING id, created_at
                """,
                email, pw_hash,
            )
    except asyncpg.UniqueViolationError:
        # Log failed signup attempt — duplicate email
        asyncio.ensure_future(_write_audit_log(
            pool,
            action="user.signup",
            success=False,
            user_type="anonymous",
            target_type="user",
            target_id=email,
            ip_address=_client_ip(request),
            details={"reason": "duplicate_email", "request_id": _get_request_id(request)},
        ))
        raise HTTPException(
            status_code=409,
            detail=_error_envelope(
                "CONFLICT",
                "An account with that email already exists.",
                _get_request_id(request),
            ),
        )

    user_id = str(row["id"])
    log.info("User registered: id=%s email=%s", user_id, email)

    # Log successful signup
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="user.signup",
        success=True,
        user_type="anonymous",
        target_type="user",
        target_id=user_id,
        ip_address=_client_ip(request),
        details={"email": email, "request_id": _get_request_id(request)},
    ))

    return JSONResponse(
        status_code=201,
        content={"user_id": user_id, "email": email, "created_at": row["created_at"].isoformat()},
    )


@auth_router.post("/login", summary="Authenticate and receive a session cookie")
async def login(
    request:  Request,
    response: Response,
    body:     LoginRequest,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    email = body.email.lower().strip()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash FROM users WHERE email = $1",
            email,
        )

    _INVALID = HTTPException(
        status_code=401,
        detail=_error_envelope(
            "UNAUTHORIZED",
            "Invalid email or password.",
            _get_request_id(request),
        ),
    )
    if row is None:
        asyncio.ensure_future(_write_audit_log(
            pool,
            action="user.login",
            success=False,
            user_type="anonymous",
            target_type="user",
            target_id=email,
            ip_address=_client_ip(request),
            details={"reason": "user_not_found", "request_id": _get_request_id(request)},
        ))
        raise _INVALID
    if not _verify_password(body.password, row["password_hash"]):
        asyncio.ensure_future(_write_audit_log(
            pool,
            action="user.login",
            success=False,
            user_type="anonymous",
            target_type="user",
            target_id=str(row["id"]),
            ip_address=_client_ip(request),
            details={"reason": "wrong_password", "request_id": _get_request_id(request)},
        ))
        raise _INVALID

    user_id = str(row["id"])
    token   = _make_session_token(user_id)

    # Log successful login
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="user.login",
        success=True,
        user_type="anonymous",
        target_type="user",
        target_id=user_id,
        ip_address=_client_ip(request),
        details={"email": email, "request_id": _get_request_id(request)},
    ))

    resp = JSONResponse(content={"status": "ok", "user_id": user_id})
    resp.set_cookie(
        key="dodman_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=(_RUNTIME_ENV() == "production"),
        max_age=60 * 60 * 24 * 7,   # 7 days
    )
    log.info("User logged in: id=%s", user_id)
    return resp


@auth_router.post("/logout", summary="Invalidate the session cookie")
async def logout(
    request:        Request,
    dodman_session: str | None = Cookie(default=None),
) -> Response:
    # Identify the user from the session token (best-effort — no DB hit)
    user_id = _decode_session_token(dodman_session) if dodman_session else "unknown"

    resp = RedirectResponse(url="/auth/login-page", status_code=303)
    resp.delete_cookie(key="dodman_session", httponly=True, samesite="lax")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"

    # Log the logout — fire-and-forget, pool may be None if DB is unreachable
    try:
        pool = await get_pool()
        asyncio.ensure_future(_write_audit_log(
            pool,
            action="user.logout",
            success=True,
            user_type="user",
            target_type="session",
            target_id=user_id or "unknown",
            ip_address=_client_ip(request),
            details={"request_id": _get_request_id(request)},
        ))
    except Exception:
        pass

    return resp


# ---------------------------------------------------------------------------
# Auth page routes (serve the HTML templates)
# ---------------------------------------------------------------------------

@auth_router.get("/login-page", include_in_schema=False)
async def login_page(request: Request):
    resp = templates.TemplateResponse(request=request, name="login.html", context={"error": None})
    # Prevent caching so the browser always fetches a fresh copy.
    # Critical: ensures back-button after logout shows this page, not the dashboard.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


@auth_router.get("/signup-page", include_in_schema=False)
async def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html", context={})


# ---------------------------------------------------------------------------
# Forgot password — request reset link
# ---------------------------------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


@auth_router.post("/forgot-password", summary="Request a password reset email")
async def forgot_password(
    request: Request,
    body:    ForgotPasswordRequest,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    email = body.email.lower().strip()

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1", email
        )

    # Always return the same response whether the email exists or not —
    # prevents account enumeration attacks.
    _SAFE_RESPONSE = JSONResponse(content={
        "message": "If an account exists for that email, a reset link has been sent."
    })

    if not user:
        # Log the attempt but return the safe generic response
        asyncio.ensure_future(_write_audit_log(
            pool, "user.forgot_password", False,
            user_type="anonymous", target_type="user",
            target_id=email, ip_address=_client_ip(request),
            details={"reason": "email_not_found", "request_id": _get_request_id(request)},
        ))
        return _SAFE_RESPONSE

    user_id = str(user["id"])

    # Invalidate any existing unused tokens for this user before issuing a new one
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE password_resets SET used = TRUE WHERE user_id = $1 AND used = FALSE",
            uuid.UUID(user_id),
        )

    # Generate a secure token and store its hash (never store raw tokens)
    raw_token  = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO password_resets (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            """,
            uuid.UUID(user_id), token_hash, expires_at,
        )

    # Build the reset link
    reset_url = f"{APP_BASE_URL}/auth/reset-password-page?token={raw_token}"

    # Send the email via Resend
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/></head>
<body style="font-family:'IBM Plex Mono',monospace;background:#07070a;color:#d0d0e0;margin:0;padding:40px;">
  <div style="max-width:520px;margin:0 auto;background:#0f0f12;border:1px solid #232329;border-radius:12px;overflow:hidden;">
    <div style="background:#16161a;padding:24px 28px;border-bottom:1px solid #232329;">
      <p style="font-size:10px;letter-spacing:.3em;text-transform:uppercase;color:#f59e0b;margin:0 0 4px;">Dodman Group</p>
      <p style="font-size:18px;font-weight:700;color:#fff;margin:0;">Reset Your Password</p>
    </div>
    <div style="padding:24px 28px;font-size:13px;line-height:1.7;color:#9a9aaa;">
      <p>We received a request to reset the password for <strong style="color:#d0d0e0;">{email}</strong>.</p>
      <p>Click the button below to set a new password. This link expires in <strong style="color:#d0d0e0;">1 hour</strong>.</p>
      <div style="text-align:center;margin:28px 0;">
        <a href="{reset_url}"
           style="background:#10b981;color:#07070a;font-weight:700;font-size:12px;
                  letter-spacing:.08em;text-transform:uppercase;padding:12px 32px;
                  border-radius:6px;text-decoration:none;display:inline-block;">
          Reset Password
        </a>
      </div>
      <p style="font-size:11px;color:#6b6b7a;">
        If you did not request this, you can safely ignore this email —
        your password will not be changed.
      </p>
      <p style="font-size:11px;color:#6b6b7a;word-break:break-all;">
        Or copy this link: {reset_url}
      </p>
    </div>
    <div style="padding:16px 28px;border-top:1px solid #232329;font-size:10px;color:#3a3a44;text-align:center;">
      Dodman Group &middot; Data Cleaning Proxy API &middot; {RESEND_FROM}
    </div>
  </div>
</body>
</html>"""

    asyncio.ensure_future(_send_email(
        to=email,
        subject="Reset your Dodman password",
        html=html,
    ))

    asyncio.ensure_future(_write_audit_log(
        pool, "user.forgot_password", True,
        user_type="anonymous", target_type="user",
        target_id=user_id, ip_address=_client_ip(request),
        details={"email": email, "request_id": _get_request_id(request)},
    ))

    return _SAFE_RESPONSE


@auth_router.get("/forgot-password-page", include_in_schema=False)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="forgot_password.html", context={})

# ---------------------------------------------------------------------------
# Forgot password — serve the reset password page
# ---------------------------------------------------------------------------

@auth_router.get("/reset-password-page", include_in_schema=False)
async def reset_password_page(
    request: Request,
    token:   str | None = None,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> Response:
    # Validate the token before serving the page so the user gets a clear
    # error immediately rather than filling out the form and then failing.
    error: str | None = None

    if not token:
        error = "Missing reset token. Please request a new password reset link."
    else:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT expires_at, used
                FROM   password_resets
                WHERE  token_hash = $1
                """,
                token_hash,
            )
        if not row:
            error = "Invalid reset link. Please request a new one."
        elif row["used"]:
            error = "This reset link has already been used. Please request a new one."
        elif row["expires_at"] < datetime.datetime.now(datetime.timezone.utc):
            error = "This reset link has expired. Please request a new one."

    return templates.TemplateResponse(
        request=request,
        name="reset_password.html",
        context={"token": token, "error": error},
    )


# ---------------------------------------------------------------------------
# Forgot password — submit new password
# ---------------------------------------------------------------------------

class ResetPasswordRequest(BaseModel):
    token:    str
    password: str


@auth_router.post("/reset-password", summary="Set a new password using a reset token")
async def reset_password(
    request: Request,
    body:    ResetPasswordRequest,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    if len(body.password) < 8:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "Password must be at least 8 characters.",
                _get_request_id(request),
            ),
        )

    token_hash = hashlib.sha256(body.token.encode()).hexdigest()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, user_id, expires_at, used
            FROM   password_resets
            WHERE  token_hash = $1
            """,
            token_hash,
        )

    _INVALID = HTTPException(
        status_code=400,
        detail=_error_envelope(
            "INVALID_TOKEN",
            "This reset link is invalid, expired, or has already been used.",
            _get_request_id(request),
        ),
    )

    if not row:
        raise _INVALID
    if row["used"]:
        raise _INVALID
    if row["expires_at"] < datetime.datetime.now(datetime.timezone.utc):
        raise _INVALID

    user_id   = str(row["user_id"])
    new_hash  = _hash_password(body.password)

    # Update password and mark token as used atomically
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                new_hash, uuid.UUID(user_id),
            )
            await conn.execute(
                "UPDATE password_resets SET used = TRUE WHERE id = $1",
                row["id"],
            )

    asyncio.ensure_future(_write_audit_log(
        pool, "user.reset_password", True,
        user_type="anonymous", target_type="user",
        target_id=user_id, ip_address=_client_ip(request),
        details={"request_id": _get_request_id(request)},
    ))

    log.info("Password reset successful: user_id=%s", user_id)
    return JSONResponse(content={
        "message": "Password updated successfully. You can now log in."
    })


# Convenience redirect from root
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/auth/login-page")


# ---------------------------------------------------------------------------
# Current-user dependency (reads the session cookie)
# ---------------------------------------------------------------------------

async def get_current_user(
    request:         Request,
    dodman_session:  str | None = Cookie(default=None),
    pool:            asyncpg.Pool = Depends(get_pool),
) -> dict:
    # For browser-facing routes (Accept: text/html) raise _NeedsLoginRedirect
    # which is caught by _login_redirect_handler and turned into a 303.
    # For API clients raise a standard 401 HTTPException with a JSON envelope.
    def _unauth() -> Exception:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return _NeedsLoginRedirect()
        return HTTPException(
            status_code=401,
            detail=_error_envelope(
                "UNAUTHORIZED",
                "You must be logged in to access this resource.",
                _get_request_id(request),
            ),
        )

    if not dodman_session:
        raise _unauth()

    user_id = _decode_session_token(dodman_session)
    if not user_id:
        raise _unauth()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT u.id, u.email, u.last_env, u.created_at,
                   s.status   AS sub_status,
                   s.plan     AS sub_plan,
                   s.current_period_end AS sub_period_end
            FROM   users u
            LEFT JOIN subscriptions s ON s.user_id = u.id
            WHERE  u.id = $1
            """,
            uuid.UUID(user_id),
        )
    if row is None:
        raise _unauth()

    return {
        "id":             str(row["id"]),
        "email":          row["email"],
        "last_env":       row["last_env"],
        "created_at":     row["created_at"],
        "sub_status":     row["sub_status"] or "none",
        "sub_plan":       row["sub_plan"]   or "free",
        "sub_period_end": row["sub_period_end"].isoformat() if row["sub_period_end"] else None,
    }


# ---------------------------------------------------------------------------
# PATCH /auth/me/env  — persist the user's preferred environment toggle
# Placed here because it depends on get_current_user defined above.
# ---------------------------------------------------------------------------

@auth_router.patch("/me/env", summary="Save preferred environment view")
async def update_last_env(
    request:      Request,
    current_user: dict          = Depends(get_current_user),
    pool:         asyncpg.Pool  = Depends(get_pool),
) -> JSONResponse:
    body = await request.json()
    env  = str(body.get("env", "")).strip().lower()
    if env not in ("test", "live"):
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "env must be 'test' or 'live'.",
                _get_request_id(request),
            ),
        )
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_env = $1 WHERE id = $2",
            env, uuid.UUID(current_user["id"]),
        )
    return JSONResponse(content={"last_env": env})


# ===========================================================================
# Key management endpoints (user-facing + internal admin)
# ===========================================================================

class CreateKeyRequest(BaseModel):
    label:       str
    tier:        str = "free"
    environment: str = "test"


@router.post(
    "/keys",
    summary="Issue a new API key",
    status_code=201,
    tags=["keys"],
)
async def create_api_key(
    request: Request,
    body:    CreateKeyRequest | None = None,
    _:       None = Depends(verify_internal_secret),
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    # Also accept form data
    content_type = request.headers.get("content-type", "")
    if body is None or "multipart" in content_type or "form" in content_type:
        form  = await request.form()
        label = str(form.get("label", "")).strip()
        tier  = str(form.get("tier", "free")).strip()
        env   = str(form.get("environment", "test")).strip()
    else:
        label = (body.label or "").strip()
        tier  = body.tier.strip()
        env   = body.environment.strip()

    if not label:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED", "'label' is required.", _get_request_id(request)
            ),
        )
    if tier not in TIER_RANK:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                f"Invalid tier '{tier}'. Must be one of: free, starter, pro.",
                _get_request_id(request),
            ),
        )
    if env not in ("test", "live"):
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "Invalid environment. Must be 'test' or 'live'.",
                _get_request_id(request),
            ),
        )

    raw    = _generate_raw_key(env)
    hashed = _hash_key(raw)
    prefix = raw[:16]

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO api_keys (key_hash, key_prefix, label, environment, tier)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, created_at
            """,
            hashed, prefix, label, env, tier,
        )

    log.info("API key issued: id=%s label=%r env=%s tier=%s", row["id"], label, env, tier)
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="api_key.issue",
        success=True,
        user_type="admin",
        target_type="api_key",
        target_id=str(row["id"]),
        ip_address=_client_ip(request),
        details={
            "key_prefix": prefix, "label": label,
            "environment": env, "tier": tier,
            "request_id": _get_request_id(request),
        },
    ))
    return JSONResponse(
        status_code=201,
        content={
            "id":          str(row["id"]),
            "label":       label,
            "tier":        tier,
            "environment": env,
            "key_prefix":  prefix,
            "api_key":     raw,
            "created_at":  row["created_at"].isoformat(),
            "warning":     "Store this key immediately. It will not be shown again.",
        },
    )


@router.post(
    "/keys/user",
    summary="Issue an API key linked to the authenticated user",
    status_code=201,
    tags=["keys"],
)
async def create_user_api_key(
    request:      Request,
    body:         CreateKeyRequest,
    current_user: dict = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    env  = body.environment.strip()
    tier = body.tier.strip()

    if env not in ("test", "live"):
        raise HTTPException(
            status_code=422,
            detail=_error_envelope("VALIDATION_FAILED",
                                   "environment must be 'test' or 'live'.",
                                   _get_request_id(request)),
        )

    # ── Paywall: live keys require an active subscription ─────────────────────
    if env == "live":
        sub_status = current_user.get("sub_status", "none")
        if sub_status != "active":
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.paywall_blocked", False,
                user_type="user", target_type="api_key",
                target_id=current_user["id"],
                ip_address=_client_ip(request),
                details={"sub_status": sub_status, "request_id": _get_request_id(request)},
            ))
            raise HTTPException(
                status_code=402,
                detail=_error_envelope(
                    "SUBSCRIPTION_REQUIRED",
                    "A live API key requires an active subscription. "
                    "Visit /dashboard/billing to subscribe.",
                    _get_request_id(request),
                ),
            )

    raw    = _generate_raw_key(env)
    hashed = _hash_key(raw)
    prefix = raw[:16]
    label  = (body.label or current_user["email"]).strip()

    async with pool.acquire() as conn:
        # Deactivate ALL existing keys for this user+environment before issuing
        # a new one — only one active key per environment is allowed.
        deactivated = await conn.execute(
            """
            UPDATE api_keys
            SET    is_active = FALSE
            WHERE  user_id = $1
            AND    environment = $2
            AND    is_active = TRUE
            """,
            uuid.UUID(current_user["id"]), env,
        )
        row = await conn.fetchrow(
            """
            INSERT INTO api_keys (user_id, key_hash, key_prefix, label, environment, tier)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, created_at
            """,
            uuid.UUID(current_user["id"]), hashed, prefix, label, env, tier,
        )

    deactivated_count = int(deactivated.split()[-1]) if deactivated else 0
    log.info(
        "Key re-issued: user=%s env=%s deactivated_previous=%d new_prefix=%s",
        current_user["id"], env, deactivated_count, prefix,
    )
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="api_key.reissue",
        success=True,
        user_type="user",
        target_type="api_key",
        target_id=str(row["id"]),
        ip_address=_client_ip(request),
        details={
            "user_id": current_user["id"],
            "key_prefix": prefix,
            "environment": env,
            "tier": tier,
            "previous_deactivated": deactivated_count,
            "request_id": _get_request_id(request),
        },
    ))
    return JSONResponse(
        status_code=201,
        content={
            "id":                  str(row["id"]),
            "label":               label,
            "environment":         env,
            "tier":                tier,
            "key_prefix":          prefix,
            "api_key":             raw,
            "created_at":          row["created_at"].isoformat(),
            "previous_deactivated": deactivated_count,
            "warning":             "Store this key immediately. It will not be shown again.",
        },
    )


@router.patch(
    "/keys/{key_id}/deactivate",
    summary="Deactivate an API key",
    tags=["keys"],
)
async def deactivate_api_key(
    key_id:  str,
    request: Request,
    _:       None = Depends(verify_internal_secret),
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="key_id must be a valid UUID.")

    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE api_keys SET is_active = FALSE WHERE id = $1", key_uuid
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"Key id={key_id} not found.")
    log.info("API key deactivated: id=%s", key_id)
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="api_key.deactivate",
        success=True,
        user_type="admin",
        target_type="api_key",
        target_id=key_id,
        ip_address=_client_ip(request),
        details={"request_id": _get_request_id(request)},
    ))
    return JSONResponse(content={"id": key_id, "is_active": False})


# ===========================================================================
# Billing / Paystack router
# ===========================================================================
# Paystack flow:
#   1. GET  /dashboard/billing       — pricing page (served from dashboard)
#   2. POST /billing/subscribe       — initialise Paystack transaction → redirect
#   3. GET  /billing/callback        — Paystack redirects here after payment
#   4. POST /billing/webhook         — Paystack posts events (charge, cancel, etc.)
# ===========================================================================

billing_router = APIRouter(prefix="/billing", tags=["billing"])

_PAYSTACK_API = "https://api.paystack.co"

_PLAN_MAP = {
    "starter": lambda: PAYSTACK_PLAN_STARTER,
    "pro":     lambda: PAYSTACK_PLAN_PRO,
}

_TIER_FROM_PLAN: dict[str, str] = {}   # populated lazily from plan codes


async def _paystack_post(endpoint: str, payload: dict) -> dict:
    """POST to Paystack API, return parsed JSON. Raises on HTTP error."""
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(
            f"{_PAYSTACK_API}{endpoint}",
            json=payload,
            headers={
                "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                "Content-Type":  "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _paystack_get(endpoint: str) -> dict:
    """GET from Paystack API."""
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(
            f"{_PAYSTACK_API}{endpoint}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
        )
        resp.raise_for_status()
        return resp.json()


async def _upsert_subscription(
    pool:       asyncpg.Pool,
    user_id:    str,
    *,
    customer_id:     str,
    subscription_id: str,
    plan_code:       str,
    status:          str,
    period_start:    datetime.datetime | None,
    period_end:      datetime.datetime | None,
    plan_name:       str,
    raw_event:       dict,
) -> None:
    """Insert or update the subscriptions row for a user."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO subscriptions
                (user_id, paystack_customer_id, paystack_subscription_id,
                 paystack_plan_code, status, plan,
                 current_period_start, current_period_end,
                 last_event_data, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                paystack_customer_id     = EXCLUDED.paystack_customer_id,
                paystack_subscription_id = EXCLUDED.paystack_subscription_id,
                paystack_plan_code       = EXCLUDED.paystack_plan_code,
                status                   = EXCLUDED.status,
                plan                     = EXCLUDED.plan,
                current_period_start     = EXCLUDED.current_period_start,
                current_period_end       = EXCLUDED.current_period_end,
                last_event_data          = EXCLUDED.last_event_data,
                updated_at               = NOW()
            """,
            uuid.UUID(user_id),
            customer_id,
            subscription_id,
            plan_code,
            status,
            plan_name,
            period_start,
            period_end,
            json.dumps(raw_event),
        )


def _plan_name_from_code(plan_code: str) -> str:
    """Resolve a Paystack plan code to our internal tier name."""
    if plan_code == PAYSTACK_PLAN_PRO:
        return "pro"
    return "starter"


# ---------------------------------------------------------------------------
# Resend email helper
# ---------------------------------------------------------------------------

async def _send_email(
    to:      str,
    subject: str,
    html:    str,
) -> bool:
    """
    Send a transactional email via Resend.
    Returns True on success, False on failure.
    Never raises — email delivery is always fire-and-forget.
    """
    if not RESEND_API_KEY:
        log.warning("RESEND_API_KEY not set — email not sent to %s", to)
        return False
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                RESEND_API_URL,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "from":    RESEND_FROM,
                    "to":      [to],
                    "subject": subject,
                    "html":    html,
                },
            )
            resp.raise_for_status()
            log.info("Email sent via Resend: to=%s subject=%r", to, subject)
            return True
    except Exception:
        log.exception("Resend email failed: to=%s subject=%r", to, subject)
        return False


# ---------------------------------------------------------------------------
# Invoice HTML builder
# ---------------------------------------------------------------------------

def _fmt_invoice_date(val: str) -> str:
    """Format an ISO timestamp or date string to 'DD Mon YYYY', or return '—'."""
    if not val:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y")
    except Exception:
        # val may already be a plain date string like "2025-06-01"
        try:
            return datetime.datetime.strptime(val[:10], "%Y-%m-%d").strftime("%d %b %Y")
        except Exception:
            return val[:10] if len(val) >= 10 else val


def _build_invoice_html(
    invoice_ref:  str,
    user_email:   str,
    plan:         str,
    amount_minor: int,
    currency:     str,
    paid_at:      str,
    period_start: str,
    period_end:   str,
) -> str:
    """
    Render a fully inline-styled HTML invoice.
    Inline styles are used throughout so the output renders correctly in both
    PDF converters (wkhtmltopdf) and email clients (Gmail, Outlook, Apple Mail)
    that strip <style> blocks.
    """
    amount_display  = f"{currency} {amount_minor / 100:,.2f}"
    now_str         = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y")
    plan_display    = plan.title() if plan else "—"
    paid_at_display = _fmt_invoice_date(paid_at) if paid_at else "—"
    ps_display      = _fmt_invoice_date(period_start)
    pe_display      = _fmt_invoice_date(period_end)

    # Shared inline style fragments
    _S_BODY  = "font-family:'IBM Plex Mono',Courier,monospace;background:#07070a;color:#d0d0e0;margin:0;padding:40px;"
    _S_CARD  = "max-width:600px;margin:0 auto;background:#0f0f12;border:1px solid #232329;border-radius:12px;overflow:hidden;"
    _S_HDR   = "background:#16161a;padding:28px 32px;border-bottom:1px solid #232329;"
    _S_BRAND = "font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:#f59e0b;margin:0 0 6px 0;"
    _S_TITLE = "font-size:22px;font-weight:700;color:#ffffff;margin:0;"
    _S_BODYD = "padding:28px 32px;"
    _S_AMT   = "font-size:26px;font-weight:700;color:#10b981;text-align:center;padding:16px 0 24px;"
    _S_ROW   = "display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #16161a;font-size:13px;"
    _S_ROW_L = "display:flex;justify-content:space-between;padding:10px 0;font-size:13px;"  # last row — no border
    _S_LBL   = "color:#6b6b7a;"
    _S_VAL   = "color:#d0d0e0;text-align:right;"
    _S_MONO  = "color:#d0d0e0;text-align:right;font-family:'IBM Plex Mono',Courier,monospace;font-size:12px;"
    _S_BADGE = ("display:inline-block;background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.4);"
                "color:#10b981;font-size:10px;padding:3px 10px;border-radius:4px;"
                "letter-spacing:.08em;text-transform:uppercase;")
    _S_FTR   = "padding:18px 32px;border-top:1px solid #232329;font-size:11px;color:#3a3a44;text-align:center;"

    def row(label: str, value: str, last: bool = False, mono_val: bool = False) -> str:
        val_style = _S_MONO if mono_val else _S_VAL
        return (
            f'<div style="{_S_ROW_L if last else _S_ROW}">'
            f'<span style="{_S_LBL}">{label}</span>'
            f'<span style="{val_style}">{value}</span>'
            f'</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Invoice {invoice_ref[:12]}</title>
</head>
<body style="{_S_BODY}">
<div style="{_S_CARD}">
  <div style="{_S_HDR}">
    <p style="{_S_BRAND}">Dodman Group</p>
    <p style="{_S_TITLE}">Invoice</p>
  </div>
  <div style="{_S_BODYD}">
    <div style="{_S_AMT}">{amount_display}</div>
    {row("Reference",    invoice_ref,    mono_val=True)}
    {row("Status",       f'<span style="{_S_BADGE}">Paid</span>')}
    {row("Billed to",    user_email)}
    {row("Plan",         plan_display)}
    {row("Paid on",      paid_at_display)}
    {row("Period start", ps_display)}
    {row("Period end",   pe_display)}
    {row("Invoice date", now_str, last=True)}
  </div>
  <div style="{_S_FTR}">Dodman Group &middot; Data Cleaning Proxy API &middot; {RESEND_FROM}</div>
</div>
</body>
</html>"""


def _build_invoice_pdf(
    invoice_ref:  str,
    user_email:   str,
    plan:         str,
    amount_minor: int,
    currency:     str,
    paid_at:      str,
    period_start: str,
    period_end:   str,
) -> bytes:
    """
    Build a styled A4 PDF invoice using reportlab (pure Python, no binaries).
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()

    # ── Colours ──────────────────────────────────────────────────────────────
    C_BG        = colors.HexColor("#07070a")
    C_CARD      = colors.HexColor("#0f0f12")
    C_BORDER    = colors.HexColor("#232329")
    C_HDR_BG    = colors.HexColor("#16161a")
    C_AMBER     = colors.HexColor("#f59e0b")
    C_WHITE     = colors.HexColor("#ffffff")
    C_MUTED     = colors.HexColor("#6b6b7a")
    C_BODY      = colors.HexColor("#d0d0e0")
    C_GREEN     = colors.HexColor("#10b981")
    C_ROW_ALT   = colors.HexColor("#0d0d10")
    C_BADGE_BG  = colors.HexColor("#0d2e22")
    C_BADGE_BDR = colors.HexColor("#1a5c3a")

    # ── Styles ────────────────────────────────────────────────────────────────
    def ps(name, **kw) -> ParagraphStyle:
        defaults = dict(fontName="Courier", fontSize=10, textColor=C_BODY,
                        leading=14, spaceAfter=0)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    S_BRAND    = ps("brand",   fontSize=8,  textColor=C_AMBER,  spaceAfter=2)
    S_TITLE    = ps("title",   fontSize=20, textColor=C_WHITE,  fontName="Courier-Bold")
    S_AMOUNT   = ps("amount",  fontSize=26, textColor=C_GREEN,  fontName="Courier-Bold",
                               alignment=TA_CENTER, spaceAfter=4)
    S_LABEL    = ps("label",   fontSize=10, textColor=C_MUTED,  alignment=TA_LEFT)
    S_VALUE    = ps("value",   fontSize=10, textColor=C_BODY,   alignment=TA_RIGHT)
    S_MONO     = ps("mono",    fontSize=9,  textColor=C_BODY,   alignment=TA_RIGHT)
    S_BADGE    = ps("badge",   fontSize=8,  textColor=C_GREEN,  alignment=TA_RIGHT,
                               fontName="Courier-Bold")
    S_FOOTER   = ps("footer",  fontSize=8,  textColor=C_MUTED,  alignment=TA_CENTER)

    # ── Derived values ────────────────────────────────────────────────────────
    amount_display  = f"{currency} {amount_minor / 100:,.2f}"
    now_str         = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y")
    plan_display    = plan.title() if plan else "—"
    paid_at_display = _fmt_invoice_date(paid_at)
    ps_display      = _fmt_invoice_date(period_start)
    pe_display      = _fmt_invoice_date(period_end)

    # ── Page setup ────────────────────────────────────────────────────────────
    W, H  = A4
    LEFT  = RIGHT = TOP = BOT = 20 * mm
    doc   = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=LEFT, rightMargin=RIGHT,
        topMargin=TOP,   bottomMargin=BOT,
    )

    card_w = W - LEFT - RIGHT

    # ── Background canvas callback ────────────────────────────────────────────
    def _draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Card background
        card_x = LEFT - 6 * mm
        card_y = BOT - 6 * mm
        card_w2 = W - LEFT - RIGHT + 12 * mm
        card_h2 = H - TOP - BOT + 12 * mm
        canvas.setFillColor(C_CARD)
        canvas.setStrokeColor(C_BORDER)
        canvas.roundRect(card_x, card_y, card_w2, card_h2, 6, fill=1, stroke=1)
        # Header band
        hdr_h = 22 * mm
        canvas.setFillColor(C_HDR_BG)
        canvas.roundRect(card_x, H - TOP - hdr_h + 6 * mm, card_w2, hdr_h + 6 * mm,
                         6, fill=1, stroke=0)
        # Clip the bottom corners of the header rectangle flat
        canvas.setFillColor(C_HDR_BG)
        canvas.rect(card_x, H - TOP - hdr_h, card_w2, 6 * mm + 1, fill=1, stroke=0)
        # Header bottom border line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(card_x, H - TOP - hdr_h, card_x + card_w2, H - TOP - hdr_h)
        canvas.restoreState()

    # ── Story ─────────────────────────────────────────────────────────────────
    story = []

    # Header
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("DODMAN GROUP", S_BRAND))
    story.append(Paragraph("Invoice", S_TITLE))
    story.append(Spacer(1, 10 * mm))

    # Amount
    story.append(Paragraph(amount_display, S_AMOUNT))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 2 * mm))

    # Detail rows — alternating background via TableStyle
    rows = [
        ("Reference",    Paragraph(invoice_ref,   S_MONO)),
        ("Status",       Paragraph("PAID",         S_BADGE)),
        ("Billed to",    Paragraph(user_email,     S_VALUE)),
        ("Plan",         Paragraph(plan_display,   S_VALUE)),
        ("Paid on",      Paragraph(paid_at_display, S_VALUE)),
        ("Period start", Paragraph(ps_display,     S_VALUE)),
        ("Period end",   Paragraph(pe_display,     S_VALUE)),
        ("Invoice date", Paragraph(now_str,        S_VALUE)),
    ]
    table_data = [
        [Paragraph(label, S_LABEL), val]
        for label, val in rows
    ]

    col_w = [card_w * 0.38, card_w * 0.62]
    tbl = Table(table_data, colWidths=col_w, repeatRows=0)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1),  C_CARD),
        ("BACKGROUND",  (0, 1), (-1, 1),   C_ROW_ALT),
        ("BACKGROUND",  (0, 3), (-1, 3),   C_ROW_ALT),
        ("BACKGROUND",  (0, 5), (-1, 5),   C_ROW_ALT),
        ("BACKGROUND",  (0, 7), (-1, 7),   C_ROW_ALT),
        # Badge cell highlight
        ("BACKGROUND",  (1, 1), (1, 1),    C_BADGE_BG),
        ("BOX",         (1, 1), (1, 1),    0.5, C_BADGE_BDR),
        ("LINEBELOW",   (0, 0), (-1, -2),  0.5, C_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1),  6),
        ("BOTTOMPADDING",(0,0), (-1, -1),  6),
        ("LEFTPADDING", (0, 0), (-1, -1),  4),
        ("RIGHTPADDING",(0, 0), (-1, -1),  4),
        ("VALIGN",      (0, 0), (-1, -1),  "MIDDLE"),
    ]))
    story.append(tbl)

    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        f"Dodman Group · Data Cleaning Proxy API · {RESEND_FROM}",
        S_FOOTER,
    ))

    doc.build(story, onFirstPage=_draw_bg, onLaterPages=_draw_bg)
    return buf.getvalue()


def _resolve_period_dates(tx: dict, sub: dict, plan: dict) -> tuple[str, str]:
    """
    Return (period_start, period_end) as ISO strings, using the best available
    source from the Paystack transaction object.

    Priority:
      1. Subscription object fields (createdAt / next_payment_date) — most accurate
      2. paid_at  as start + plan interval as end (typical for new subscriptions
         where the sub object hasn't fully populated yet)
      3. Empty strings (rendered as "—" by the invoice builder)
    """
    # 1 — subscription object
    ps = sub.get("createdAt") or sub.get("created_at") or ""
    pe = sub.get("next_payment_date") or sub.get("nextPaymentDate") or ""

    if ps and pe:
        return ps, pe

    # 2 — derive from paid_at + plan interval
    paid_at_raw = tx.get("paid_at") or tx.get("paidAt") or ""
    if paid_at_raw:
        try:
            start_dt = datetime.datetime.fromisoformat(paid_at_raw.replace("Z", "+00:00"))
            ps = start_dt.isoformat()

            # Determine billing interval from plan object
            interval = (plan.get("interval") or "monthly").lower()
            if interval in ("annually", "yearly"):
                end_dt = start_dt.replace(year=start_dt.year + 1)
            elif interval == "quarterly":
                # Add ~91 days
                end_dt = start_dt + datetime.timedelta(days=91)
            elif interval in ("weekly",):
                end_dt = start_dt + datetime.timedelta(weeks=1)
            else:
                # Default: monthly — advance one month
                month = start_dt.month + 1
                year  = start_dt.year + (month - 1) // 12
                month = ((month - 1) % 12) + 1
                try:
                    end_dt = start_dt.replace(year=year, month=month)
                except ValueError:
                    # e.g. Jan 31 → Feb 28
                    import calendar
                    last_day = calendar.monthrange(year, month)[1]
                    end_dt = start_dt.replace(year=year, month=month, day=last_day)
            pe = end_dt.isoformat()
        except Exception:
            pass

    return ps, pe


async def _send_invoice_email(
    to:          str,
    invoice_ref: str,
    plan:        str,
    amount_minor: int,
    currency:    str,
    paid_at:     str,
    period_start: str = "",
    period_end:   str = "",
) -> None:
    """Render invoice HTML and send it via Resend."""
    html = _build_invoice_html(
        invoice_ref, to, plan, amount_minor, currency,
        paid_at, period_start, period_end,
    )
    amount_display = f"{currency} {amount_minor / 100:,.2f}"
    await _send_email(
        to=to,
        subject=f"Your Dodman invoice — {amount_display} · {invoice_ref[:12]}",
        html=html,
    )


async def _send_subscription_email(
    to:      str,
    subject: str,
    heading: str,
    body:    str,
    cta_text: str  = "",
    cta_url:  str  = "",
) -> None:
    """Generic transactional email for subscription lifecycle events."""
    cta_block = ""
    if cta_text and cta_url:
        cta_block = (
            f'''<div style="text-align:center;margin:24px 0;">
              <a href="{cta_url}" style="background:#10b981;color:#07070a;font-weight:700;
                 font-size:12px;letter-spacing:.08em;text-transform:uppercase;padding:11px 28px;
                 border-radius:6px;text-decoration:none;">{cta_text}</a>
            </div>'''
        )
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<style>
  body{{font-family:'IBM Plex Mono',monospace;background:#07070a;color:#d0d0e0;margin:0;padding:40px;}}
  .card{{max-width:560px;margin:0 auto;background:#0f0f12;border:1px solid #232329;border-radius:12px;overflow:hidden;}}
  .hdr{{background:#16161a;padding:24px 28px;border-bottom:1px solid #232329;}}
  .brand{{font-size:10px;letter-spacing:.3em;text-transform:uppercase;color:#f59e0b;margin:0 0 4px;}}
  .heading{{font-size:18px;font-weight:700;color:#fff;margin:0;}}
  .body{{padding:24px 28px;font-size:13px;line-height:1.7;color:#9a9aaa;}}
  .footer{{padding:16px 28px;border-top:1px solid #232329;font-size:10px;color:#3a3a44;text-align:center;}}
</style>
</head><body>
<div class="card">
  <div class="hdr"><p class="brand">Dodman Group</p><p class="heading">{heading}</p></div>
  <div class="body">{body}{cta_block}</div>
  <div class="footer">Dodman Group · Data Cleaning Proxy API · Questions? Reply to this email.</div>
</div>
</body></html>"""
    await _send_email(to=to, subject=subject, html=html)


# ---------------------------------------------------------------------------
# POST /billing/subscribe — start a Paystack subscription checkout
# ---------------------------------------------------------------------------

@billing_router.post("/subscribe", summary="Initialise a Paystack subscription checkout")
async def billing_subscribe(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    body     = await request.json()
    plan_key = str(body.get("plan", "starter")).strip().lower()

    if plan_key not in _PLAN_MAP:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                f"Invalid plan '{plan_key}'. Must be 'starter' or 'pro'.",
                _get_request_id(request),
            ),
        )

    plan_code = _PLAN_MAP[plan_key]()
    if not plan_code:
        raise HTTPException(
            status_code=503,
            detail=_error_envelope(
                "CONFIGURATION_ERROR",
                f"PAYSTACK_PLAN_{plan_key.upper()} is not configured on this server.",
                _get_request_id(request),
            ),
        )

    callback_url = f"{APP_BASE_URL}/billing/callback"

    # Fetch the plan from Paystack to get the amount — required by
    # /transaction/initialize even when a plan code is provided.
    # Paystack returns amount in the smallest currency unit (e.g. kobo).
    try:
        plan_data   = await _paystack_get(f"/plan/{plan_code}")
        plan_amount = plan_data.get("data", {}).get("amount", 0)
        if not plan_amount or plan_amount <= 0:
            raise HTTPException(
                status_code=503,
                detail=_error_envelope(
                    "CONFIGURATION_ERROR",
                    f"Could not determine plan amount for '{plan_key}'. "
                    "Check that the plan code is correct in your Paystack dashboard.",
                    _get_request_id(request),
                ),
            )
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        log.error("Paystack plan fetch failed: %s", exc.response.text)
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Could not retrieve plan details from Paystack. "
                "Verify your plan code in PAYSTACK_PLAN_STARTER / PAYSTACK_PLAN_PRO.",
                _get_request_id(request),
            ),
        )

    try:
        data = await _paystack_post("/transaction/initialize", {
            "email":        current_user["email"],
            "amount":       plan_amount,   # required — in smallest currency unit
            "plan":         plan_code,
            "callback_url": callback_url,
            "metadata": {
                "user_id":    current_user["id"],
                "plan":       plan_key,
                "service":    "data_cleaning_proxy",
                "product":    "data-cleaner-api",
            },
        })
    except httpx.HTTPStatusError as exc:
        log.error("Paystack initialise failed: %s", exc.response.text)
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Could not initialise payment. Please try again.",
                _get_request_id(request),
            ),
        )

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.subscribe_initiated", True,
        user_type="user", target_type="subscription",
        target_id=current_user["id"],
        ip_address=_client_ip(request),
        details={"plan": plan_key, "request_id": _get_request_id(request)},
    ))

    return JSONResponse(content={
        "authorization_url": data["data"]["authorization_url"],
        "access_code":       data["data"]["access_code"],
        "reference":         data["data"]["reference"],
    })


# ---------------------------------------------------------------------------
# GET /billing/callback — Paystack redirects here after the hosted page
# ---------------------------------------------------------------------------

@billing_router.get("/callback", include_in_schema=False)
async def billing_callback(
    request:   Request,
    trxref:    str | None = None,
    reference: str | None = None,
    pool:      asyncpg.Pool = Depends(get_pool),
) -> Response:
    # Note: no get_current_user dependency — session cookie may be absent
    # after returning from Paystack's external hosted page.
    ref = trxref or reference
    if not ref:
        return RedirectResponse(url="/dashboard/billing?status=error&reason=missing_ref")

    try:
        data = await _paystack_get(f"/transaction/verify/{ref}")
    except Exception:
        log.exception("Paystack verify failed for ref=%s", ref)
        return RedirectResponse(url="/dashboard/billing?status=error&reason=verify_failed")

    tx   = data.get("data", {})
    stat = tx.get("status")

    if stat != "success":
        return RedirectResponse(
            url=f"/dashboard/billing?status=failed&reason={stat}"
        )

    # Resolve user from the verified transaction's customer email
    # This is safe — we're trusting Paystack's verified response, not user input
    customer    = tx.get("customer", {}) or {}
    cust_email  = (customer.get("email") or "").lower().strip()

    if not cust_email:
        log.error("billing_callback: no customer email in verified transaction ref=%s", ref)
        return RedirectResponse(url="/auth/login-page?reason=callback_error")

    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1", cust_email
        )

    if not user_row:
        log.error("billing_callback: no user found for email=%s ref=%s", cust_email, ref)
        return RedirectResponse(url="/auth/login-page?reason=callback_error")

    user_id = str(user_row["id"])

    # Pull subscription details from the verified transaction
    sub      = tx.get("subscription", {}) or {}
    plan     = tx.get("plan",         {}) or {}

    if isinstance(plan, str):
        plan = {"plan_code": plan}

    plan_code = plan.get("plan_code", "")
    plan_name = _plan_name_from_code(plan_code)

    # Period may come as ISO strings or missing — handle both
    def _parse_dt(val: str | None) -> datetime.datetime | None:
        if not val:
            return None
        try:
            return datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None

    period_start_str, period_end_str = _resolve_period_dates(tx, sub, plan)

    await _upsert_subscription(
        pool,
        user_id,
        customer_id=str(customer.get("id", "")),
        subscription_id=str(sub.get("id", "")),
        plan_code=plan_code,
        status="active",
        period_start=_parse_dt(period_start_str),
        period_end=_parse_dt(period_end_str),
        plan_name=plan_name,
        raw_event=tx,
    )

    # Upgrade live API key tier
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE api_keys SET tier = $1
            WHERE  user_id = $2 AND environment = 'live' AND is_active = TRUE
            """,
            plan_name, uuid.UUID(user_id),
        )

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.subscribed", True,
        user_type="user", target_type="subscription",
        target_id=user_id,
        ip_address=_client_ip(request),
        details={"plan": plan_name, "plan_code": plan_code, "ref": ref},
    ))
    # Send invoice for the initial payment
    asyncio.ensure_future(_send_invoice_email(
        to=cust_email,
        invoice_ref=ref,
        plan=plan_name,
        amount_minor=tx.get("amount", 0),
        currency=tx.get("currency", ""),
        paid_at=tx.get("paid_at") or tx.get("paidAt") or "",
        period_start=period_start_str,
        period_end=period_end_str,
    ))

    log.info("Subscription activated via callback: user=%s plan=%s", user_id, plan_name)

    # Redirect to login page with a flag so the frontend can show a
    # "payment successful — please log in" message rather than a plain login form
    return RedirectResponse(
        url="/auth/login-page?billing=success",
        status_code=303
    )


# ---------------------------------------------------------------------------
# POST /billing/webhook — Paystack event stream (unsigned verification)
# ---------------------------------------------------------------------------

@billing_router.post("/webhook", include_in_schema=False)
async def billing_webhook(
    request: Request,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Receive and verify Paystack webhook events.

    Paystack signs the payload with HMAC-SHA512 using your secret key.
    We verify the signature before trusting any payload content.
    Responds 200 immediately (Paystack retries on non-200).
    """
    import hmac as _hmac

    body_bytes = await request.body()
    sig_header = request.headers.get("x-paystack-signature", "")

    if PAYSTACK_WEBHOOK_SECRET:
        expected = _hmac.new(
            PAYSTACK_WEBHOOK_SECRET.encode(),
            body_bytes,
            "sha512",
        ).hexdigest()
        if not _hmac.compare_digest(expected, sig_header):
            log.warning("Paystack webhook: signature mismatch — rejected")
            # Return 200 so Paystack doesn't keep retrying a spoofed payload
            return JSONResponse(content={"status": "ignored"})

    try:
        event = json.loads(body_bytes)
    except json.JSONDecodeError:
        return JSONResponse(content={"status": "bad_json"})

    event_type = event.get("event", "")
    data       = event.get("data", {})
    log.info("Paystack webhook received: event=%s", event_type)

    # ── Resolve user_id from customer email ───────────────────────────────────
    async def _user_id_from_email(email: str) -> str | None:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id FROM users WHERE email = $1", email.lower().strip()
            )
        return str(row["id"]) if row else None

    customer    = data.get("customer", {}) or {}
    cust_email  = customer.get("email", "")
    cust_id     = str(customer.get("id", ""))
    plan        = data.get("plan", {}) or {}

    # Paystack sometimes returns "plan" as a bare plan-code string rather than
    # an object.  Normalise to a dict so .get() calls below are always safe.
    if isinstance(plan, str):
        plan = {"plan_code": plan}

    plan_code   = plan.get("plan_code", "")
    plan_name   = _plan_name_from_code(plan_code)

    def _parse_dt(val: str | None) -> datetime.datetime | None:
        if not val:
            return None
        try:
            return datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None

    # ── charge.success ────────────────────────────────────────────────────────
    if event_type == "charge.success":
        # Filter by product metadata — only process payments intended for
        # this product. Other products sharing the same Paystack credentials
        # must embed their own product identifier in metadata at init time.
        event_metadata = data.get("metadata") or {}
        event_product  = event_metadata.get("product", "")
        if event_product != "data-cleaner-api":
            log.info(
                "Paystack charge.success ignored — product=%r (expected 'data-cleaner-api')",
                event_product,
            )
            return JSONResponse(content={"status": "ignored"})

        user_id = await _user_id_from_email(cust_email)
        if user_id:
            sub_code = data.get("subscription", {}) or {}
            await _upsert_subscription(
                pool, user_id,
                customer_id=cust_id,
                subscription_id=str(sub_code.get("id", "")),
                plan_code=plan_code,
                status="active",
                period_start=_parse_dt(data.get("paidAt")),
                period_end=_parse_dt(sub_code.get("next_payment_date")),
                plan_name=plan_name,
                raw_event=data,
            )
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.charge_success", True,
                user_type="user", target_type="subscription",
                target_id=user_id,
                ip_address="paystack-webhook",
                details={"plan": plan_name, "amount": data.get("amount"), "event": event_type},
            ))
            # Send invoice email
            asyncio.ensure_future(_send_invoice_email(
                to=cust_email,
                invoice_ref=data.get("reference", ""),
                plan=plan_name,
                amount_minor=data.get("amount", 0),
                currency=data.get("currency", ""),
                paid_at=data.get("paidAt") or data.get("paid_at") or "",
                period_start=data.get("paidAt") or "",
                period_end=(sub_code.get("next_payment_date") or ""),
            ))

    # ── subscription.create ───────────────────────────────────────────────────
    elif event_type == "subscription.create":
        user_id = await _user_id_from_email(cust_email)
        if user_id:
            await _upsert_subscription(
                pool, user_id,
                customer_id=cust_id,
                subscription_id=str(data.get("subscription_code", "")),
                plan_code=plan_code,
                status="active",
                period_start=_parse_dt(data.get("createdAt")),
                period_end=_parse_dt(data.get("next_payment_date")),
                plan_name=plan_name,
                raw_event=data,
            )
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.subscription_created", True,
                user_type="user", target_type="subscription",
                target_id=user_id,
                ip_address="paystack-webhook",
                details={"plan": plan_name, "event": event_type},
            ))
            asyncio.ensure_future(_send_subscription_email(
                to=cust_email,
                subject=f"Welcome to Dodman {plan_name.title()} — subscription active",
                heading="Subscription Activated",
                body=(
                    f"<p>Your <strong style=\"color:#10b981\">{plan_name.title()}</strong> subscription "
                    f"is now active. Your <code>dk_live_</code> key is ready to use.</p>"
                    f"<p>You can manage your subscription, view invoices, and monitor usage from your dashboard.</p>"
                ),
                cta_text="Go to Dashboard",
                cta_url=f"{APP_BASE_URL}/dashboard/",
            ))

    # ── subscription.disable / subscription.not_renew ─────────────────────────
    elif event_type in ("subscription.disable", "subscription.not_renew"):
        user_id = await _user_id_from_email(cust_email)
        if user_id:
            new_status = "cancelled" if event_type == "subscription.disable" else "non-renewing"
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE subscriptions
                    SET    status = $1, last_event_data = $2::jsonb, updated_at = NOW()
                    WHERE  user_id = $3
                    """,
                    new_status, json.dumps(data), uuid.UUID(user_id),
                )
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.subscription_cancelled", True,
                user_type="user", target_type="subscription",
                target_id=user_id,
                ip_address="paystack-webhook",
                details={"new_status": new_status, "event": event_type},
            ))
            cancel_msg = (
                "<p>Auto-renewal has been disabled. Your access remains active until "
                "the end of your current billing period.</p>"
                "<p>You can reactivate at any time from your dashboard.</p>"
                if new_status == "non-renewing"
                else "<p>Your subscription has been cancelled. Your live API key will stop working. "
                     "You can re-subscribe at any time.</p>"
            )
            asyncio.ensure_future(_send_subscription_email(
                to=cust_email,
                subject="Your Dodman subscription has been cancelled",
                heading="Subscription Cancelled",
                body=cancel_msg,
                cta_text="Re-subscribe",
                cta_url=f"{APP_BASE_URL}/dashboard/",
            ))

    # ── invoice.payment_failed ────────────────────────────────────────────────
    elif event_type == "invoice.payment_failed":
        user_id = await _user_id_from_email(cust_email)
        if user_id:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE subscriptions
                    SET    status = 'attention', last_event_data = $1::jsonb, updated_at = NOW()
                    WHERE  user_id = $2
                    """,
                    json.dumps(data), uuid.UUID(user_id),
                )
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.payment_failed", False,
                user_type="user", target_type="subscription",
                target_id=user_id,
                ip_address="paystack-webhook",
                details={"event": event_type, "amount": data.get("amount")},
            ))
            asyncio.ensure_future(_send_subscription_email(
                to=cust_email,
                subject="Action required: Dodman payment failed",
                heading="Payment Failed",
                body=(
                    "<p>We were unable to charge your card for your Dodman subscription renewal.</p>"
                    "<p>Please update your payment method on the Paystack customer portal to avoid "
                    "losing access to your live API key.</p>"
                    "<p>If payment is not resolved within 3 days, your subscription will be suspended.</p>"
                ),
                cta_text="Update Payment Method",
                cta_url=f"{APP_BASE_URL}/dashboard/",
            ))

    return JSONResponse(content={"status": "ok"})


# ---------------------------------------------------------------------------
# GET /billing/portal  — current user's subscription status (JSON)
# ---------------------------------------------------------------------------

@billing_router.get("/portal", summary="Get current subscription status")
async def billing_portal(
    current_user: dict = Depends(get_current_user),
) -> JSONResponse:
    return JSONResponse(content={
        "sub_status":     current_user.get("sub_status", "none"),
        "sub_plan":       current_user.get("sub_plan", "free"),
        "sub_period_end": current_user.get("sub_period_end"),
    })


# ---------------------------------------------------------------------------
# GET /billing/invoices — invoices scoped strictly to the authenticated user.
#
# Ownership is enforced at two levels:
#   1. Paystack query filtered by the user's registered email address
#   2. Each transaction's customer email is verified against current_user
#      before inclusion — so even if Paystack returns unexpected rows,
#      they are stripped out before the response is sent.
#
# This endpoint is for dashboard use only.
# Admin-wide invoice listing is at GET /billing/admin/invoices (godkey only).
# ---------------------------------------------------------------------------

@billing_router.get("/invoices", summary="List paid invoices for the authenticated user only")
async def billing_invoices(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
    page:         int          = 1,
    per_page:     int          = 20,
) -> JSONResponse:
    user_email = current_user["email"].lower().strip()

    # Confirm the user has a subscription row before hitting Paystack —
    # avoids unnecessary external calls for users who never subscribed.
    async with pool.acquire() as conn:
        sub_row = await conn.fetchrow(
            "SELECT paystack_customer_id FROM subscriptions WHERE user_id = $1",
            uuid.UUID(current_user["id"]),
        )

    if not sub_row:
        # No subscription record at all — return empty list, not an error.
        return JSONResponse(content={"invoices": [], "total": 0, "page": page, "pages": 1})

    try:
        data = await _paystack_get(
            f"/transaction?email={user_email}"
            f"&page={page}&perPage={min(per_page, 100)}&status=success"
        )
    except httpx.HTTPStatusError:
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Could not fetch invoices from Paystack.",
                _get_request_id(request),
            ),
        )

    raw  = data.get("data", []) or []
    meta = data.get("meta", {})

    invoices = []
    for tx in raw:
        # Filter by product — only show transactions that belong to data-cleaner-api
        tx_metadata = tx.get("metadata") or {}
        product     = tx_metadata.get("product", "")
        service     = tx_metadata.get("service", "")
        # Accept if product matches, OR if product is absent but service matches
        # (covers transactions made before the product field was added)
        if product and product != "data-cleaner-api":
            continue
        if not product and service != "data_cleaning_proxy":
            continue

        # Ownership double-check (already there)
        tx_customer = tx.get("customer", {}) or {}
        tx_email    = (tx_customer.get("email") or "").lower().strip()
        if tx_email and tx_email != user_email:
            continue

        invoices.append({
            "reference":      tx.get("reference", ""),
            "amount_minor":   tx.get("amount", 0),
            "amount_display": f"{tx.get('currency', '')} {tx.get('amount', 0) / 100:,.2f}",
            "currency":       tx.get("currency", ""),
            "paid_at":        tx.get("paid_at") or tx.get("paidAt"),
            "plan":           _plan_name_from_code(
                                tx.get("plan") if isinstance(tx.get("plan"), str)
                                else (tx.get("plan") or {}).get("plan_code", "")
                            ),
            "download_url":   f"/billing/invoice/{tx.get('reference', '')}/download",
            "email_url":      f"/billing/invoice/{tx.get('reference', '')}/email",
        })

    return JSONResponse(content={
        "invoices": invoices,
        "total":    meta.get("total", len(invoices)),
        "page":     page,
        "pages":    meta.get("pageCount", 1),
    })


# ---------------------------------------------------------------------------
# GET /billing/admin/invoices — all invoices across all users (admin/godkey)
# Protected by X-Internal-Secret. Never exposed in the user dashboard.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/admin/invoices",
    summary="List all invoices across all users — admin only",
    dependencies=[Depends(verify_internal_secret)],
)
async def billing_admin_invoices(
    request:  Request,
    pool:     asyncpg.Pool = Depends(get_pool),
    page:     int          = 1,
    per_page: int          = 50,
) -> JSONResponse:
    """
    Returns paginated Paystack transaction history for every customer,
    joined with local user data so each row includes user_id and email.

    Protected by X-Internal-Secret — godkey dashboard use only.
    """
    try:
        data = await _paystack_get(
            f"/transaction?page={page}&perPage={min(per_page, 100)}&status=success"
        )
    except httpx.HTTPStatusError:
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Could not fetch transactions from Paystack.",
                _get_request_id(request),
            ),
        )

    raw  = data.get("data", []) or []
    meta = data.get("meta", {})

    # Build a lookup of email → user_id from our local users table
    emails = list({
        (tx.get("customer") or {}).get("email", "").lower()
        for tx in raw
        if (tx.get("customer") or {}).get("email")
    })
    email_to_uid: dict[str, str] = {}
    if emails:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, email FROM users WHERE email = ANY($1::text[])",
                emails,
            )
        email_to_uid = {r["email"].lower(): str(r["id"]) for r in rows}

    invoices = []
    for tx in raw:
        cust      = tx.get("customer", {}) or {}
        cust_email = (cust.get("email") or "").lower()
        invoices.append({
            "reference":      tx.get("reference", ""),
            "amount_minor":   tx.get("amount", 0),
            "amount_display": f"{tx.get('currency', '')} {tx.get('amount', 0) / 100:,.2f}",
            "currency":       tx.get("currency", ""),
            "paid_at":        tx.get("paid_at") or tx.get("paidAt"),
            "plan":           _plan_name_from_code(
                                  tx.get("plan") if isinstance(tx.get("plan"), str)
                                  else (tx.get("plan") or {}).get("plan_code", "")
                              ),
            "customer_email": cust_email,
            "user_id":        email_to_uid.get(cust_email, None),
            "channel":        tx.get("channel", ""),
        })

    return JSONResponse(content={
        "invoices": invoices,
        "total":    meta.get("total", len(invoices)),
        "page":     page,
        "pages":    meta.get("pageCount", 1),
    })


# ---------------------------------------------------------------------------
# GET /billing/invoice/{reference}/download
# Generate and stream an HTML invoice as a downloadable file.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/invoice/{reference}/download",
    summary="Download an invoice as an HTML file",
    include_in_schema=False,
)
async def invoice_download(
    reference:    str,
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> Response:
    # Verify the transaction exists and belongs to this user
    try:
        data = await _paystack_get(f"/transaction/verify/{reference}")
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=404, detail="Invoice not found.")

    tx       = data.get("data", {})
    customer = tx.get("customer", {}) or {}
    tx_email = (customer.get("email") or "").lower().strip()

    if tx_email and tx_email != current_user["email"].lower():
        raise HTTPException(status_code=403, detail="This invoice does not belong to your account.")

    if tx.get("status") != "success":
        raise HTTPException(status_code=400, detail="Invoice only available for successful transactions.")

    plan      = tx.get("plan", {}) or {}
    sub       = tx.get("subscription", {}) or {}
    if isinstance(plan, str):
        plan = {"plan_code": plan}
    plan_name = _plan_name_from_code(plan.get("plan_code", ""))

    period_start, period_end = _resolve_period_dates(tx, sub, plan)

    html = _build_invoice_html(
        invoice_ref=reference,
        user_email=current_user["email"],
        plan=plan_name,
        amount_minor=tx.get("amount", 0),
        currency=tx.get("currency", ""),
        paid_at=tx.get("paid_at") or tx.get("paidAt") or "",
        period_start=period_start,
        period_end=period_end,
    )

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.invoice_downloaded", True,
        user_type="user", target_type="invoice",
        target_id=reference, ip_address=_client_ip(request),
        details={"reference": reference},
    ))

    # Convert to PDF using reportlab (pure Python — no external binaries)
    try:
        pdf_bytes = _build_invoice_pdf(
            invoice_ref=reference,
            user_email=current_user["email"],
            plan=plan_name,
            amount_minor=tx.get("amount", 0),
            currency=tx.get("currency", ""),
            paid_at=tx.get("paid_at") or tx.get("paidAt") or "",
            period_start=period_start,
            period_end=period_end,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=invoice-{reference[:12]}.pdf"},
        )
    except Exception:
        log.exception("PDF generation failed for reference=%s — falling back to HTML", reference)
        return Response(
            content=html.encode(),
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=invoice-{reference[:12]}.html"},
        )


# ---------------------------------------------------------------------------
# POST /billing/invoice/{reference}/email
# Re-send an invoice to the user's registered email address.
# ---------------------------------------------------------------------------

@billing_router.post(
    "/invoice/{reference}/email",
    summary="Re-send a specific invoice to the account email",
)
async def invoice_email(
    reference:    str,
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    try:
        data = await _paystack_get(f"/transaction/verify/{reference}")
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=404, detail="Invoice not found.")

    tx       = data.get("data", {})
    customer = tx.get("customer", {}) or {}
    tx_email = (customer.get("email") or "").lower().strip()

    if tx_email and tx_email != current_user["email"].lower():
        raise HTTPException(status_code=403, detail="This invoice does not belong to your account.")

    if tx.get("status") != "success":
        raise HTTPException(status_code=400, detail="Invoice only available for successful transactions.")

    plan      = tx.get("plan", {}) or {}
    sub       = tx.get("subscription", {}) or {}
    if isinstance(plan, str):
        plan = {"plan_code": plan}
    plan_name = _plan_name_from_code(plan.get("plan_code", ""))

    period_start, period_end = _resolve_period_dates(tx, sub, plan)

    asyncio.ensure_future(_send_invoice_email(
        to=current_user["email"],
        invoice_ref=reference,
        plan=plan_name,
        amount_minor=tx.get("amount", 0),
        currency=tx.get("currency", ""),
        paid_at=tx.get("paid_at") or tx.get("paidAt") or "",
        period_start=period_start,
        period_end=period_end,
    ))

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.invoice_emailed", True,
        user_type="user", target_type="invoice",
        target_id=reference, ip_address=_client_ip(request),
        details={"to": current_user["email"], "reference": reference},
    ))

    return JSONResponse(content={
        "sent_to": current_user["email"],
        "reference": reference,
        "message": f"Invoice {reference[:12]}… sent to {current_user['email']}",
    })


# ---------------------------------------------------------------------------
# GET /billing/verify/{reference}
# Manually verify a specific Paystack transaction reference.
# Useful when a user completes payment but the callback was missed (network
# hiccup, browser closed, etc.).  Idempotent — safe to call multiple times.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/verify/{reference}",
    summary="Verify a Paystack transaction by reference and sync subscription state",
)
async def billing_verify(
    reference:    str,
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Calls Paystack GET /transaction/verify/:reference and, if the transaction
    status is 'success', upserts the subscription row exactly as the callback
    does.  Returns the full verification payload so the caller can inspect it.

    Use this when:
      - A user paid but the dashboard still shows 'no subscription'
      - You want to confirm a specific charge reference from your records
    """
    try:
        data = await _paystack_get(f"/transaction/verify/{reference}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail=_error_envelope(
                    "NOT_FOUND",
                    f"Transaction reference '{reference}' not found on Paystack.",
                    _get_request_id(request),
                ),
            )
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Paystack verification request failed. Try again shortly.",
                _get_request_id(request),
            ),
        )

    tx        = data.get("data", {})
    tx_status = tx.get("status", "")
    amount    = tx.get("amount", 0)          # in kobo / smallest currency unit
    currency  = tx.get("currency", "")
    paid_at   = tx.get("paid_at") or tx.get("paidAt")

    sub      = tx.get("subscription", {}) or {}
    customer = tx.get("customer",     {}) or {}
    plan     = tx.get("plan",         {}) or {}

    # Paystack sometimes returns "plan" as a bare plan-code string rather than
    # an object.  Normalise to a dict so .get() calls below are always safe.
    if isinstance(plan, str):
        plan = {"plan_code": plan}

    plan_code = plan.get("plan_code", "")
    plan_name = _plan_name_from_code(plan_code)

    def _parse_dt(val: str | None) -> datetime.datetime | None:
        if not val:
            return None
        try:
            return datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None

    period_start_str, period_end_str = _resolve_period_dates(tx, sub, plan)

    synced = False
    if tx_status == "success":
        # Only sync if this transaction belongs to the requesting user
        tx_email = (customer.get("email") or "").lower().strip()
        if tx_email and tx_email != current_user["email"].lower():
            raise HTTPException(
                status_code=403,
                detail=_error_envelope(
                    "FORBIDDEN",
                    "This transaction does not belong to your account.",
                    _get_request_id(request),
                ),
            )
        await _upsert_subscription(
            pool,
            current_user["id"],
            customer_id=str(customer.get("id", "")),
            subscription_id=str(sub.get("id", "")),
            plan_code=plan_code,
            status="active",
            period_start=_parse_dt(period_start_str),
            period_end=_parse_dt(period_end_str),
            plan_name=plan_name,
            raw_event=tx,
        )
        # Also upgrade the live key tier
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE api_keys SET tier = $1
                WHERE  user_id = $2 AND environment = 'live' AND is_active = TRUE
                """,
                plan_name, uuid.UUID(current_user["id"]),
            )
        synced = True
        asyncio.ensure_future(_write_audit_log(
            pool, "billing.verify_synced", True,
            user_type="user", target_type="subscription",
            target_id=current_user["id"],
            ip_address=_client_ip(request),
            details={"reference": reference, "plan": plan_name, "amount": amount},
        ))

    return JSONResponse(content={
        "reference":         reference,
        "transaction_status": tx_status,
        "amount":            amount,
        "currency":          currency,
        "paid_at":           paid_at,
        "plan":              plan_name,
        "synced_to_account": synced,
        "message": (
            "Subscription activated and account updated."
            if synced
            else f"Transaction status is '{tx_status}' — no changes made."
        ),
    })


# ---------------------------------------------------------------------------
# GET /billing/transactions
# List raw Paystack transaction history for the authenticated user's email.
# Shows all charges ever made — successful, failed, abandoned.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/transactions",
    summary="List Paystack transaction history for this account",
)
async def billing_transactions(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    page:         int          = 1,
    per_page:     int          = 20,
) -> JSONResponse:
    """
    Proxies Paystack GET /transaction?email=...&page=...&perPage=... and
    returns a normalised list.  Useful for confirming individual charge
    deposits and checking their exact timestamps and amounts.

    Each item in the response carries:
      - reference        → use with GET /billing/verify/{reference}
      - status           → 'success' | 'failed' | 'abandoned'
      - amount_display   → human-readable e.g. "KES 2,000.00"
      - paid_at          → ISO timestamp of the successful charge
    """
    if per_page > 100:
        per_page = 100  # Paystack hard cap

    try:
        data = await _paystack_get(
            f"/transaction?email={current_user['email']}"
            f"&page={page}&perPage={per_page}&status=success"
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Could not fetch transaction list from Paystack.",
                _get_request_id(request),
            ),
        )

    raw_list = data.get("data", []) or []
    meta     = data.get("meta", {})

    def _fmt_amount(amount_minor: int, currency: str) -> str:
        """Convert smallest-unit integer to display string."""
        major = amount_minor / 100
        return f"{currency} {major:,.2f}"

    normalised = [
        {
            "reference":      tx.get("reference", ""),
            "status":         tx.get("status", ""),
            "amount_minor":   tx.get("amount", 0),
            "amount_display": _fmt_amount(tx.get("amount", 0), tx.get("currency", "")),
            "currency":       tx.get("currency", ""),
            "paid_at":        tx.get("paid_at") or tx.get("paidAt"),
            "channel":        tx.get("channel", ""),
            "plan_code":      tx.get("plan") if isinstance(tx.get("plan"), str)
                              else (tx.get("plan", {}) or {}).get("plan_code", ""),
        }
        for tx in raw_list
    ]

    return JSONResponse(content={
        "transactions": normalised,
        "total":        meta.get("total", len(normalised)),
        "page":         page,
        "per_page":     per_page,
        "pages":        meta.get("pageCount", 1),
    })


# ---------------------------------------------------------------------------
# GET /billing/subscription
# Pull the live subscription record directly from Paystack (not our DB cache)
# and return the authoritative state.  Also re-syncs our DB row.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/subscription",
    summary="Fetch live subscription state from Paystack and re-sync local record",
)
async def billing_subscription_status(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Fetches the subscription directly from Paystack using the subscription_id
    stored in our local subscriptions row.  Re-syncs status, next payment date,
    and amount.  Use this to confirm what Paystack actually holds as truth,
    bypassing our cached DB state entirely.
    """
    # Fetch our local record first to get the Paystack subscription_id
    async with pool.acquire() as conn:
        local = await conn.fetchrow(
            """
            SELECT paystack_subscription_id, paystack_customer_id,
                   paystack_plan_code, status, plan,
                   current_period_start, current_period_end, updated_at
            FROM   subscriptions
            WHERE  user_id = $1
            """,
            uuid.UUID(current_user["id"]),
        )

    if not local:
        return JSONResponse(content={
            "local_status":  "none",
            "paystack_data": None,
            "message":       "No subscription record found. Subscribe at /billing/subscribe.",
        })

    sub_id = local["paystack_subscription_id"]

    # If we have a subscription_id, fetch live data from Paystack
    paystack_data = None
    if sub_id:
        try:
            resp       = await _paystack_get(f"/subscription/{sub_id}")
            paystack_data = resp.get("data", {})

            # Re-sync our local row with authoritative Paystack state
            ps_status = paystack_data.get("status", local["status"])

            def _parse_dt(val: str | None) -> datetime.datetime | None:
                if not val:
                    return None
                try:
                    return datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
                except Exception:
                    return None

            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE subscriptions
                    SET    status               = $1,
                           current_period_end   = $2,
                           last_event_data      = $3::jsonb,
                           updated_at           = NOW()
                    WHERE  user_id = $4
                    """,
                    ps_status,
                    _parse_dt(paystack_data.get("next_payment_date")),
                    json.dumps(paystack_data),
                    uuid.UUID(current_user["id"]),
                )
            asyncio.ensure_future(_write_audit_log(
                pool, "billing.status_synced", True,
                user_type="user", target_type="subscription",
                target_id=current_user["id"],
                ip_address=_client_ip(request),
                details={"paystack_status": ps_status},
            ))
        except httpx.HTTPStatusError:
            # Paystack returned 404 — subscription no longer exists there
            paystack_data = None

    def _maybe_iso(val: Any) -> str | None:
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    return JSONResponse(content={
        "local_status":         local["status"],
        "local_plan":           local["plan"],
        "local_period_end":     _maybe_iso(local["current_period_end"]),
        "local_last_synced":    _maybe_iso(local["updated_at"]),
        "paystack_sub_id":      sub_id,
        "paystack_live_data":   paystack_data,
        "days_until_renewal":   (
            max(0, (local["current_period_end"] - datetime.datetime.now(datetime.timezone.utc)).days)
            if local["current_period_end"] else None
        ),
    })


# ---------------------------------------------------------------------------
# GET /billing/due
# Internal/admin endpoint: list all subscriptions whose next payment is within
# N days (default 3).  Useful for sending renewal reminder emails or flagging
# accounts that may churn.  Requires X-Internal-Secret header.
# ---------------------------------------------------------------------------

@billing_router.get(
    "/due",
    summary="List subscriptions due for renewal within N days (admin)",
    dependencies=[Depends(verify_internal_secret)],
)
async def billing_due(
    request:  Request,
    days:     int          = 3,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Returns all active subscriptions whose current_period_end falls within
    the next `days` days.  Protected by X-Internal-Secret.

    Useful for:
      - Cron job that sends renewal reminder emails
      - Monitoring dashboard showing upcoming renewals
      - Identifying at-risk accounts before auto-charge
    """
    if days < 0 or days > 90:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "'days' must be between 0 and 90.",
                _get_request_id(request),
            ),
        )

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                s.id,
                s.user_id,
                u.email,
                s.plan,
                s.status,
                s.paystack_subscription_id,
                s.current_period_end,
                s.current_period_start,
                EXTRACT(EPOCH FROM (s.current_period_end - NOW())) / 86400 AS days_remaining
            FROM subscriptions s
            JOIN users u ON u.id = s.user_id
            WHERE s.status IN ('active', 'non-renewing', 'attention')
            AND   s.current_period_end IS NOT NULL
            AND   s.current_period_end <= NOW() + ($1 || ' days')::interval
            ORDER BY s.current_period_end ASC
            """,
            str(days),
        )

    def _maybe_iso(val: Any) -> str | None:
        return val.isoformat() if val else None

    result = [
        {
            "subscription_id":       str(r["id"]),
            "user_id":               str(r["user_id"]),
            "email":                 r["email"],
            "plan":                  r["plan"],
            "status":                r["status"],
            "paystack_sub_id":       r["paystack_subscription_id"],
            "current_period_end":    _maybe_iso(r["current_period_end"]),
            "current_period_start":  _maybe_iso(r["current_period_start"]),
            "days_remaining":        round(float(r["days_remaining"] or 0), 1),
        }
        for r in rows
    ]

    return JSONResponse(content={
        "window_days": days,
        "count":       len(result),
        "due":         result,
    })


# ---------------------------------------------------------------------------
# POST /billing/cancel
# User-initiated cancellation: calls Paystack to disable auto-renewal, then
# marks the local subscription as 'non-renewing'.  The subscription stays
# active until current_period_end — access is not cut off immediately.
# ---------------------------------------------------------------------------

@billing_router.post(
    "/cancel",
    summary="Cancel the current subscription (disables auto-renewal at period end)",
)
async def billing_cancel(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    """
    Calls Paystack POST /subscription/disable to stop auto-renewal, then sets
    local status to 'non-renewing'.

    The user retains full access until current_period_end.  Their dk_live_ key
    continues to work.  On period end, the next webhook (subscription.disable)
    will set status to 'cancelled' and the live key becomes inaccessible.
    """
    # Fetch local subscription to get the Paystack identifiers
    async with pool.acquire() as conn:
        local = await conn.fetchrow(
            """
            SELECT paystack_subscription_id, paystack_customer_id,
                   status, current_period_end
            FROM   subscriptions
            WHERE  user_id = $1
            """,
            uuid.UUID(current_user["id"]),
        )

    if not local:
        raise HTTPException(
            status_code=404,
            detail=_error_envelope(
                "NOT_FOUND",
                "No active subscription found for this account.",
                _get_request_id(request),
            ),
        )

    if local["status"] in ("cancelled", "non-renewing"):
        return JSONResponse(content={
            "status":  local["status"],
            "message": "Subscription is already cancelled or set to not renew.",
            "access_until": local["current_period_end"].isoformat() if local["current_period_end"] else None,
        })

    sub_id  = local["paystack_subscription_id"]
    cust_id = local["paystack_customer_id"]

    # Call Paystack to disable auto-renewal
    try:
        await _paystack_post("/subscription/disable", {
            "code":  sub_id,
            "token": cust_id,
        })
    except httpx.HTTPStatusError as exc:
        log.error("Paystack cancel failed: %s", exc.response.text)
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Paystack could not process the cancellation. Please try again.",
                _get_request_id(request),
            ),
        )

    # Mark locally as non-renewing — access continues until period end
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE subscriptions
            SET    status = 'non-renewing', updated_at = NOW()
            WHERE  user_id = $1
            """,
            uuid.UUID(current_user["id"]),
        )

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.cancelled", True,
        user_type="user", target_type="subscription",
        target_id=current_user["id"],
        ip_address=_client_ip(request),
        details={
            "paystack_sub_id": sub_id,
            "access_until": local["current_period_end"].isoformat() if local["current_period_end"] else None,
            "request_id": _get_request_id(request),
        },
    ))

    log.info("Subscription cancelled: user=%s sub_id=%s", current_user["id"], sub_id)
    return JSONResponse(content={
        "status":        "non-renewing",
        "access_until":  local["current_period_end"].isoformat() if local["current_period_end"] else None,
        "message": (
            "Auto-renewal disabled. Your subscription remains active until the end "
            "of the current billing period."
        ),
    })


# ---------------------------------------------------------------------------
# POST /billing/reactivate  (admin)
# Re-enable an auto-renewal that was previously cancelled via Paystack.
# Requires X-Internal-Secret — only support staff can reactivate on behalf
# of a user, as Paystack's enable endpoint needs the subscription_code + token.
# ---------------------------------------------------------------------------

@billing_router.post(
    "/reactivate",
    summary="Re-enable auto-renewal for a cancelled subscription (admin)",
    dependencies=[Depends(verify_internal_secret)],
)
async def billing_reactivate(
    request: Request,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    body    = await request.json()
    user_id = str(body.get("user_id", "")).strip()
    if not user_id:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED", "'user_id' is required.", _get_request_id(request)
            ),
        )

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED", "'user_id' must be a valid UUID.", _get_request_id(request)
            ),
        )

    async with pool.acquire() as conn:
        local = await conn.fetchrow(
            "SELECT paystack_subscription_id, paystack_customer_id, status FROM subscriptions WHERE user_id = $1",
            uid,
        )

    if not local:
        raise HTTPException(
            status_code=404,
            detail=_error_envelope("NOT_FOUND", "No subscription found for this user.", _get_request_id(request)),
        )

    sub_id  = local["paystack_subscription_id"]
    cust_id = local["paystack_customer_id"]

    try:
        await _paystack_post("/subscription/enable", {
            "code":  sub_id,
            "token": cust_id,
        })
    except httpx.HTTPStatusError as exc:
        log.error("Paystack reactivate failed: %s", exc.response.text)
        raise HTTPException(
            status_code=502,
            detail=_error_envelope(
                "PAYMENT_GATEWAY_ERROR",
                "Paystack could not re-enable the subscription.",
                _get_request_id(request),
            ),
        )

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE subscriptions SET status = 'active', updated_at = NOW() WHERE user_id = $1",
            uid,
        )

    asyncio.ensure_future(_write_audit_log(
        pool, "billing.reactivated", True,
        user_type="admin", target_type="subscription",
        target_id=user_id,
        ip_address=_client_ip(request),
        details={"paystack_sub_id": sub_id, "request_id": _get_request_id(request)},
    ))

    return JSONResponse(content={
        "user_id": user_id,
        "status":  "active",
        "message": "Subscription re-enabled. Auto-renewal is active.",
    })


# ===========================================================================
# Module 4 — Dashboard route
# ===========================================================================

dash_router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@dash_router.get("/", summary="User dashboard")
async def dashboard(
    request:      Request,
    current_user: dict = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
):
    uid = uuid.UUID(current_user["id"])

    async with pool.acquire() as conn:
        keys = await conn.fetch(
            """
            SELECT id, key_prefix, environment, tier, is_active, created_at, last_used_at
            FROM   api_keys
            WHERE  user_id = $1
            ORDER  BY created_at DESC
            """,
            uid,
        )
        # Fetch test and live ledger rows separately for split-tab display
        ledger_test_rows = await conn.fetch(
            """
            SELECT bl.timestamp, bl.rows_in, bl.rows_out, bl.file_type,
                   bl.duration_ms, bl.key_prefix
            FROM   billing_ledger bl
            JOIN   api_keys ak ON ak.id = bl.api_key_id
            WHERE  ak.user_id = $1
            AND    bl.key_prefix LIKE 'dk!_test!_%' ESCAPE '!'
            ORDER  BY bl.timestamp DESC
            LIMIT  50
            """,
            uid,
        )
        ledger_live_rows = await conn.fetch(
            """
            SELECT bl.timestamp, bl.rows_in, bl.rows_out, bl.file_type,
                   bl.duration_ms, bl.key_prefix
            FROM   billing_ledger bl
            JOIN   api_keys ak ON ak.id = bl.api_key_id
            WHERE  ak.user_id = $1
            AND    bl.key_prefix LIKE 'dk!_live!_%' ESCAPE '!'
            ORDER  BY bl.timestamp DESC
            LIMIT  50
            """,
            uid,
        )

    def _serialise_key(k: asyncpg.Record) -> dict:
        return {
            "id":           str(k["id"]),
            "key_prefix":   k["key_prefix"],
            "environment":  k["environment"],
            "tier":         k["tier"],
            "is_active":    k["is_active"],
            "created_at":   k["created_at"].isoformat(),
            "last_used_at": k["last_used_at"].isoformat() if k["last_used_at"] else None,
        }

    def _serialise_ledger(r: asyncpg.Record) -> dict:
        return {
            "timestamp":   r["timestamp"].isoformat(),
            "rows_in":     r["rows_in"],
            "rows_out":    r["rows_out"],
            "file_type":   r["file_type"],
            "duration_ms": r["duration_ms"],
            "key_prefix":  r["key_prefix"],
        }

    # Detect billing query params for post-payment banner
    billing_alert = request.query_params.get("billing", "")

    resp = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":           current_user,
            "default_env":    current_user.get("last_env", "test"),
            "sub_status":     current_user.get("sub_status", "none"),
            "sub_plan":       current_user.get("sub_plan", "free"),
            "sub_period_end": current_user.get("sub_period_end"),
            "paystack_public_key": PAYSTACK_PUBLIC_KEY,
            "billing_alert":  billing_alert,
            "api_keys":       [_serialise_key(k) for k in keys],
            "ledger_test":    [_serialise_ledger(r) for r in ledger_test_rows],
            "ledger_live":    [_serialise_ledger(r) for r in ledger_live_rows],
        },
    )
    # Authenticated page — never cache so back-button after logout always
    # hits the server and gets redirected to login via get_current_user.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


@dash_router.get("/api-docs", summary="Client integration documentation", include_in_schema=False)
async def api_docs_page(
    request:      Request,
    current_user: dict = Depends(get_current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="api_docs.html",
        context={"user": current_user},
    )


@dash_router.get("/data-cleaner", summary="Data cleaning tool", include_in_schema=False)
async def data_cleaner_page(
    request:      Request,
    current_user: dict = Depends(get_current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"user": current_user},
    )


# ===========================================================================
# Parsing helpers
# ===========================================================================

def _decode_bytes(data: bytes, filename: str = "") -> str:
    """
    Decode raw file bytes to a Python str, auto-detecting encoding.

    Strategy:
      1. Try UTF-8 with BOM (utf-8-sig) — covers most modern files.
      2. Try plain UTF-8.
      3. Fall back to charset_normalizer which handles Latin-1, UTF-16,
         Windows-1252, Shift-JIS, CP1256 (Arabic), and hundreds more.
      4. Last resort: decode with 'replace' so we never raise on bad bytes.
    """
    # Fast path — most files are UTF-8
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            pass

    # charset_normalizer auto-detection
    result = _detect_encoding(data).best()
    if result is not None:
        detected = result.encoding or "utf-8"
        log.info("Encoding detected: %s for file %r", detected, filename)
        try:
            return data.decode(detected)
        except (UnicodeDecodeError, LookupError):
            pass

    # Final fallback — never crash on encoding
    log.warning("Encoding unknown for %r — decoding with replacement chars", filename)
    return data.decode("utf-8", errors="replace")


def _parse_csv(data: bytes, filename: str = "") -> Sheet:
    text   = _decode_bytes(data, filename)
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _parse_xlsx(data: bytes) -> Sheet:
    wb   = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws   = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(c) if c is not None else f"col_{i}" for i, c in enumerate(rows[0])]
    return [dict(zip(headers, row)) for row in rows[1:]]


def parse_file(filename: str, data: bytes) -> tuple[Sheet, str]:
    """Returns (sheet, file_type) where file_type is 'csv' or 'xlsx'."""
    lower = filename.lower()
    if lower.endswith(".csv"):
        return _parse_csv(data, filename), "csv"
    if lower.endswith(".xlsx"):
        return _parse_xlsx(data), "xlsx"
    raise HTTPException(
        status_code=415,
        detail="Unsupported file type. Only .csv and .xlsx are accepted.",
    )


# ===========================================================================
# Rule engine  (unchanged from v1)
# ===========================================================================

def _to_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_KE_PHONE_RE = re.compile(r"^254[71]\d{8}$")
_EXCEL_EPOCH = datetime.date(1899, 12, 30)
_DATE_FORMATS = [
    "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y",
    "%d.%m.%Y", "%Y/%m/%d", "%d %b %Y", "%d %B %Y",
    "%b %d, %Y", "%B %d, %Y",
]


def clean_phone_ke(value: Any) -> str | None:
    if value is None:
        return None
    raw    = str(int(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else str(value)
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return None
    if digits.startswith("0") and len(digits) == 10:
        digits = "254" + digits[1:]
    elif len(digits) == 9 and digits[0] in ("7", "1"):
        digits = "254" + digits
    elif digits.startswith("254") and len(digits) == 12:
        pass
    else:
        return None
    return digits if _KE_PHONE_RE.match(digits) else None


def clean_name(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned.title() if cleaned else None


def clean_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.date().isoformat()
    if isinstance(value, datetime.date):
        return value.isoformat()
    raw_str = str(value).strip()
    if re.match(r"^\d{1,6}(\.\d+)?$", raw_str):
        try:
            serial = int(float(raw_str))
            if 1 <= serial <= 2958465:
                parsed = _EXCEL_EPOCH + datetime.timedelta(days=serial)
                if parsed.year >= 1900:
                    return parsed.isoformat()
        except (ValueError, OverflowError):
            pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(raw_str, fmt).date().isoformat()
        except ValueError:
            continue
    return None


_TYPED_RULES = {
    "PHONE", "PHONE_INTL", "NAME", "DATE", "CURRENCY",
    "EMAIL", "EMAIL_NORMALIZE",
    "MASK", "ENCRYPT",
    "KE_MPESA_ID", "KE_COUNTY",
    "US_ZIP", "US_SSN",
}

# ---------------------------------------------------------------------------
# KE locale
# ---------------------------------------------------------------------------
_KE_COUNTIES: set[str] = {
    "mombasa","kwale","kilifi","tana river","lamu","taita taveta","garissa",
    "wajir","mandera","marsabit","isiolo","meru","tharaka-nithi","embu",
    "kitui","machakos","makueni","nyandarua","nyeri","kirinyaga",
    "murang'a","kiambu","turkana","west pokot","samburu","trans nzoia",
    "uasin gishu","elgeyo-marakwet","nandi","baringo","laikipia","nakuru",
    "narok","kajiado","kericho","bomet","kakamega","vihiga","bungoma",
    "busia","siaya","kisumu","homa bay","migori","kisii","nyamira","nairobi",
}
_KE_COUNTY_CANONICAL: dict[str, str] = {c: c.title() for c in _KE_COUNTIES}
_KE_COUNTY_ALIASES: dict[str, str] = {
    "nairobi city": "Nairobi", "nairobi county": "Nairobi",
    "muranga": "Murang'a",     "murang a": "Murang'a",
    "tharaka nithi": "Tharaka-Nithi",
    "elgeyo marakwet": "Elgeyo-Marakwet",
    "taita/taveta": "Taita Taveta",
}
_KE_MPESA_RE = re.compile(r"^[A-Z0-9]{10}$")


def clean_ke_mpesa_id(value: Any) -> dict:
    """Validate/normalise M-Pesa transaction ID (10-char alphanumeric, e.g. RK12345678)."""
    if value is None:
        return {"mpesa_id": None, "valid": False, "reason": "empty"}
    raw = re.sub(r"\s+", "", str(value).upper())
    if not raw:
        return {"mpesa_id": None, "valid": False, "reason": "empty"}
    if _KE_MPESA_RE.match(raw):
        return {"mpesa_id": raw, "valid": True, "reason": None}
    return {"mpesa_id": raw, "valid": False,
            "reason": f"expected 10 alphanumeric chars, got {len(raw)}"}


def clean_ke_county(value: Any) -> str | None:
    """Normalise a Kenyan county name to its official title-case form."""
    if value is None:
        return None
    raw = str(value).strip().lower()
    if not raw:
        return None
    if raw in _KE_COUNTY_CANONICAL:
        return _KE_COUNTY_CANONICAL[raw]
    if raw in _KE_COUNTY_ALIASES:
        return _KE_COUNTY_ALIASES[raw]
    stripped = re.sub(r"\s+county$", "", raw)
    if stripped in _KE_COUNTY_CANONICAL:
        return _KE_COUNTY_CANONICAL[stripped]
    return None


# ---------------------------------------------------------------------------
# US locale
# ---------------------------------------------------------------------------
_US_ZIP_RE = re.compile(r"^\d{5}(?:-\d{4})?$")


def clean_us_zip(value: Any) -> dict:
    """Validate and normalise a US ZIP code. Returns {zip, valid, zip4}."""
    if value is None:
        return {"zip": None, "valid": False, "zip4": None}
    raw = str(value).strip()
    if re.match(r"^\d{9}$", raw):           # 9-digit run → ZIP+4
        raw = f"{raw[:5]}-{raw[5:]}"
    if _US_ZIP_RE.match(raw):
        parts = raw.split("-")
        return {"zip": parts[0], "valid": True,
                "zip4": parts[1] if len(parts) > 1 else None}
    return {"zip": raw, "valid": False, "zip4": None}


def clean_us_ssn(value: Any) -> dict:
    """Validate and mask a US SSN. Never returns the full value — only {ssn_masked, valid}."""
    if value is None:
        return {"ssn_masked": None, "valid": False}
    raw = re.sub(r"[^0-9]", "", str(value).strip())
    if len(raw) != 9:
        return {"ssn_masked": None, "valid": False}
    area = raw[:3]
    if area in ("000", "666") or area.startswith("9"):
        return {"ssn_masked": None, "valid": False}
    if raw[3:5] == "00" or raw[5:] == "0000":
        return {"ssn_masked": None, "valid": False}
    return {"ssn_masked": f"***-**-{raw[5:]}", "valid": True}


# ---------------------------------------------------------------------------
# PII — MASK and ENCRYPT
# ---------------------------------------------------------------------------
def clean_mask(value: Any, rule_str: str = "MASK") -> str | None:
    """
    MASK       → replace all characters with *
    MASK:4     → keep last 4 characters visible  (e.g. ****5678)
    MASK:4:X   → keep last 4 visible, use X as mask char (e.g. XXXX5678)
    """
    if value is None:
        return None
    s = str(value)
    if not s:
        return s
    parts   = rule_str.split(":")
    visible = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    char    = parts[2][:1] if len(parts) > 2 and parts[2] else "*"
    keep    = min(max(0, visible), len(s))
    return char * (len(s) - keep) + s[-keep:] if keep else char * len(s)


def clean_encrypt(value: Any, salt: str = "") -> str | None:
    """
    One-way SHA-256 hash, optionally salted via X-Crypto-Salt header or ENCRYPT:<salt>.
    Returns hex digest. Zero-knowledge — irreversible by design.
    """
    if value is None:
        return None
    s = str(value)
    if not s:
        return None
    return hashlib.sha256((salt + s).encode()).hexdigest()




def clean_phone_intl(value: Any, default_region: str = "KE") -> str | None:
    """
    Normalise any international phone number to E.164 format (+254...).
    Falls back to the KE-specific cleaner for unrecognised numbers.
    default_region is used when the number has no country code prefix.
    """
    if value is None:
        return None
    raw = str(int(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else str(value)
    raw = raw.strip()
    if not raw:
        return None
    try:
        parsed = phonenumbers.parse(raw, default_region)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        pass
    # Fallback to KE-specific cleaner
    return clean_phone_ke(value)


# Currency symbol → ISO 4217 code map (extend as needed)
_CURRENCY_SYMBOLS: dict[str, str] = {
    "$":    "USD",
    "US$":  "USD",
    "€":    "EUR",
    "£":    "GBP",
    "¥":    "JPY",
    "₦":    "NGN",
    "KSh":  "KES",
    "KES":  "KES",
    "Ksh":  "KES",
    "TSh":  "TZS",
    "UGX":  "UGX",
    "USh":  "UGX",
    "ZAR":  "ZAR",
    "R":    "ZAR",
    "GHS":  "GHS",
    "GH₵":  "GHS",
    "ETB":  "ETB",
    "MAD":  "MAD",
    "EGP":  "EGP",
    "INR":  "INR",
    "₹":    "INR",
    "AUD":  "AUD",
    "A$":   "AUD",
    "CAD":  "CAD",
    "C$":   "CAD",
    "CHF":  "CHF",
    "SEK":  "SEK",
    "NOK":  "NOK",
    "DKK":  "DKK",
    "AED":  "AED",
    "SAR":  "SAR",
    "BRL":  "BRL",
    "R$":   "BRL",
    "MXN":  "MXN",
    "MX$":  "MXN",
    "SGD":  "SGD",
    "S$":   "SGD",
    "HKD":  "HKD",
    "HK$":  "HKD",
    "CNY":  "CNY",
    "¥":    "CNY",
}
# Sort longest-first so "KSh" is tried before "K"
_CURRENCY_SYMBOL_LIST = sorted(_CURRENCY_SYMBOLS.keys(), key=len, reverse=True)


def clean_currency(value: Any) -> dict | None:
    """
    Parse a currency value and return {"amount": float, "currency": "ISO"}.
    Returns None if the value can't be parsed.
    Examples: "$1,234.56" → {"amount": 1234.56, "currency": "USD"}
              "KSh 5000"  → {"amount": 5000.0,  "currency": "KES"}
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None

    detected_iso: str = ""

    # Try longest symbol first
    for sym in _CURRENCY_SYMBOL_LIST:
        if raw.upper().startswith(sym.upper()):
            detected_iso = _CURRENCY_SYMBOLS[sym]
            raw = raw[len(sym):].strip()
            break
        if raw.upper().endswith(sym.upper()):
            detected_iso = _CURRENCY_SYMBOLS[sym]
            raw = raw[:-len(sym)].strip()
            break

    # Remove formatting characters and parse the number
    num_str = re.sub(r"[,_\s]", "", raw)
    try:
        amount = float(num_str)
    except (ValueError, TypeError):
        return None

    return {"amount": amount, "currency": detected_iso or ""}


# RFC 5322-compatible simplified email regex
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def clean_email(value: Any) -> dict:
    """
    Validate and normalise an email address.
    Returns {"email": str, "valid": bool, "reason": str|None}.

    Checks performed:
      1. Basic RFC 5322 structure (local@domain.tld)
      2. No consecutive dots in local part or domain
      3. Domain has at least one dot (rejects 'user@localhost')
      4. Local part ≤ 64 chars, full address ≤ 254 chars (RFC 5321)
      5. Normalises to lowercase

    Note: This is a structural check. For deliverability verification
    (MX record lookup) set rule to EMAIL_VERIFY instead.
    """
    if value is None:
        return {"email": None, "valid": False, "reason": "empty"}

    raw = str(value).strip().lower()
    if not raw:
        return {"email": None, "valid": False, "reason": "empty"}

    if len(raw) > 254:
        return {"email": raw, "valid": False, "reason": "address too long (>254 chars)"}

    if not _EMAIL_RE.match(raw):
        return {"email": raw, "valid": False, "reason": "invalid format"}

    local, domain = raw.rsplit("@", 1)

    if len(local) > 64:
        return {"email": raw, "valid": False, "reason": "local part too long (>64 chars)"}

    if ".." in local:
        return {"email": raw, "valid": False, "reason": "consecutive dots in local part"}

    if ".." in domain:
        return {"email": raw, "valid": False, "reason": "consecutive dots in domain"}

    if "." not in domain:
        return {"email": raw, "valid": False, "reason": "domain has no TLD"}

    return {"email": raw, "valid": True, "reason": None}


def clean_email_normalize(value: Any) -> str | None:
    """
    Lightweight version: just normalise casing and strip whitespace.
    Returns the cleaned email string, or None if value is empty.
    No validation — use EMAIL for full validation.
    """
    if value is None:
        return None
    raw = str(value).strip().lower()
    return raw if raw else None


def apply_typed_rule(rule: str, value: Any, crypto_salt: str = "") -> Any:
    if rule == "PHONE":           return clean_phone_ke(value)
    if rule == "PHONE_INTL":      return clean_phone_intl(value)
    if rule == "NAME":            return clean_name(value)
    if rule == "DATE":            return clean_date(value)
    if rule == "CURRENCY":        return clean_currency(value)
    if rule == "EMAIL":           return clean_email(value)
    if rule == "EMAIL_NORMALIZE": return clean_email_normalize(value)
    if rule == "KE_MPESA_ID":     return clean_ke_mpesa_id(value)
    if rule == "KE_COUNTY":       return clean_ke_county(value)
    if rule == "US_ZIP":          return clean_us_zip(value)
    if rule == "US_SSN":          return clean_us_ssn(value)
    if rule == "MASK" or rule.startswith("MASK:"):
        return clean_mask(value, rule_str=rule)
    if rule == "ENCRYPT" or rule.startswith("ENCRYPT:"):
        parts = rule.split(":", 1)
        salt  = parts[1] if len(parts) > 1 else crypto_salt
        return clean_encrypt(value, salt=salt)
    if rule.startswith("PHONE_INTL:"):
        region = rule.split(":", 1)[1].strip().upper() or "KE"
        return clean_phone_intl(value, default_region=region)
    return apply_rule(rule, value)



def apply_rule(rule: str, value: Any) -> Any:
    if rule == "strip":        return str(value).strip() if value is not None else value
    if rule == "lowercase":    return str(value).lower() if value is not None else value
    if rule == "uppercase":    return str(value).upper() if value is not None else value
    if rule == "title_case":   return str(value).title() if value is not None else value
    if rule == "to_int":
        n = _to_number(value); return int(n) if n is not None else None
    if rule == "to_float":     return _to_number(value)
    if rule == "drop_empty":   return value
    if rule.startswith("fill_value:"):
        fill = rule.split(":", 1)[1]
        return fill if (value is None or str(value).strip() == "") else value
    if rule.startswith("clamp:"):
        parts = rule.split(":")
        lo = _to_number(parts[1]) if len(parts) > 1 and parts[1] else None
        hi = _to_number(parts[2]) if len(parts) > 2 and parts[2] else None
        n  = _to_number(value)
        if n is None: return value
        if lo is not None: n = max(lo, n)
        if hi is not None: n = min(hi, n)
        return n
    if rule.startswith("regex:"):
        _, pattern, replacement = rule.split(":", 2)
        return re.sub(pattern, replacement, str(value)) if value is not None else value
    return value


def process_row(row: Row, column_rules: dict[str, list[str]], crypto_salt: str = "") -> Row:
    out: Row = {}
    for col, value in row.items():
        rules = column_rules.get(col)
        if rules is None:
            out[col] = str(value).strip() if value is not None else value
        else:
            current = value
            for rule in rules:
                if rule in _TYPED_RULES or rule.startswith(("MASK:", "ENCRYPT:", "PHONE_INTL:")):
                    current = apply_typed_rule(rule, current, crypto_salt=crypto_salt)
                else:
                    current = apply_rule(rule, current)
            out[col] = current
    return out


def _column_numerics(sheet: Sheet, col: str) -> list[float]:
    return [
        float(row[col])
        for row in sheet
        if col in row and row[col] is not None and _to_number(row[col]) is not None
    ]


def apply_fill_stat(sheet: Sheet, col: str, stat: str) -> Sheet:
    nums = _column_numerics(sheet, col)
    if not nums: return sheet
    fill = statistics.mean(nums) if stat == "fill_mean" else statistics.median(nums)
    for row in sheet:
        v = row.get(col)
        if v is None or str(v).strip() == "":
            row[col] = fill
    return sheet


def clean_sheet(
    sheet:        Sheet,
    column_rules: dict[str, list[str]],
    dedupe_all:   bool = False,
    crypto_salt:  str  = "",
) -> Sheet:
    stat_rules  = {"fill_mean", "fill_median"}
    rules_pass1 = {
        col: [r for r in rules if r not in stat_rules and r != "dedupe"]
        for col, rules in column_rules.items()
    }
    sheet = [process_row(row, rules_pass1, crypto_salt=crypto_salt) for row in sheet]

    for col, rules in column_rules.items():
        for rule in rules:
            if rule in stat_rules:
                sheet = apply_fill_stat(sheet, col, rule)

    drop_cols = {col for col, rules in column_rules.items() if "drop_empty" in rules}
    if drop_cols:
        sheet = [
            row for row in sheet
            if not any(
                col in row and (row[col] is None or str(row[col]).strip() == "")
                for col in drop_cols
            )
        ]

    # ── Deduplication ────────────────────────────────────────────────────────
    # dedupe_all=True  → deduplicate on every column (whole-row match)
    # "dedupe" rule    → deduplicate on that specific column only
    if dedupe_all:
        seen:    set[tuple] = set()
        deduped: Sheet      = []
        for row in sheet:
            key = tuple(str(v) for v in row.values())
            if key not in seen:
                seen.add(key)
                deduped.append(row)
        sheet = deduped
    else:
        dedupe_cols = [col for col, rules in column_rules.items() if "dedupe" in rules]
        if dedupe_cols:
            seen    = set()
            deduped = []
            for row in sheet:
                key = tuple(str(row.get(col, "")) for col in dedupe_cols)
                if key not in seen:
                    seen.add(key)
                    deduped.append(row)
            sheet = deduped

    return sheet


# ===========================================================================
# Serialisers
# ===========================================================================

def _to_csv_bytes(sheet: Sheet) -> bytes:
    if not sheet: return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(sheet[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(sheet)
    return buf.getvalue().encode()


def _sanitise_for_json(sheet: Sheet) -> Sheet:
    clean = []
    for row in sheet:
        clean.append({
            k: (None if isinstance(v, float) and (math.isnan(v) or math.isinf(v)) else v)
            for k, v in row.items()
        })
    return clean


def resolve_config(header_config: str | None, form_config: str | None) -> dict:
    raw = header_config or form_config
    if not raw:
        return {"columns": {}, "output_format": "json"}
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON config: {exc}") from exc
    cfg.setdefault("columns", {})
    cfg.setdefault("output_format", "json")
    return cfg


# ===========================================================================
# Webhook dispatcher — exponential backoff + dead-letter queue
# ===========================================================================

# Retry schedule in seconds: 30s → 5 min → 30 min
_WEBHOOK_RETRY_DELAYS = [30, 300, 1800]


async def _dispatch_webhook(
    url:         str,
    payload:     list[Row],
    api_key_id:  str | None = None,
    key_prefix:  str        = "",
    job_id:      str | None = None,
) -> None:
    """
    POST cleaned rows to the client's webhook URL.
    Retries: 30 s → 5 min → 30 min. After all attempts, writes to dead-letter
    table and marks the job as failed.
    """

    async def _set_job_status(status: str, error: str | None = None) -> None:
        if not job_id:
            return
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    """UPDATE clean_jobs
                       SET status=$1, error_message=$2, updated_at=NOW()
                       WHERE id=$3""",
                    status, error, uuid.UUID(job_id),
                )
        except Exception:
            log.exception("Failed to update job status job_id=%s", job_id)

    await _set_job_status("processing")
    last_error: str = ""
    total_attempts  = 1 + len(_WEBHOOK_RETRY_DELAYS)

    for attempt in range(total_attempts):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                log.info("Webhook delivered: url=%s status=%s rows=%d attempt=%d job_id=%s",
                         url, response.status_code, len(payload), attempt + 1, job_id)
                await _set_job_status("delivered")
                return

        except httpx.TimeoutException:
            last_error = f"Timeout on attempt {attempt + 1}"
            log.warning("Webhook timeout (attempt %d/%d): url=%s", attempt + 1, total_attempts, url)
        except httpx.HTTPStatusError as exc:
            last_error = f"HTTP {exc.response.status_code} on attempt {attempt + 1}"
            log.warning("Webhook rejected (attempt %d/%d): url=%s status=%s",
                        attempt + 1, total_attempts, url, exc.response.status_code)
            if exc.response.status_code < 500:
                break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc} on attempt {attempt + 1}"
            log.exception("Webhook error (attempt %d/%d): url=%s", attempt + 1, total_attempts, url)

        # Wait before the next retry (skip sleep after the last attempt)
        if attempt < len(_WEBHOOK_RETRY_DELAYS):
            delay = _WEBHOOK_RETRY_DELAYS[attempt]
            log.info("Webhook retry in %ds: url=%s", delay, url)
            await asyncio.sleep(delay)

    log.error("Webhook failed after %d attempts — writing to DLQ: url=%s rows=%d",
              total_attempts, url, len(payload))
    await _set_job_status("failed", error=last_error)
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO webhook_dead_letter
                       (api_key_id, key_prefix, webhook_url, payload_rows, attempts, last_error)
                   VALUES ($1,$2,$3,$4,$5,$6)""",
                uuid.UUID(api_key_id) if api_key_id else None,
                key_prefix, url, len(payload), total_attempts, last_error,
            )
    except Exception:
        log.exception("Failed to write to DLQ for url=%s", url)


# ===========================================================================
# Module 2 — /clean endpoint with perf_counter telemetry
# ===========================================================================

@router.post(
    "/clean",
    summary="Upload and clean a CSV or XLSX file",
    responses={
        200: {"description": "Cleaned file streamed directly (no webhook)"},
        202: {"description": "Processing queued; payload POSTed to X-Webhook-URL"},
        400: {"description": "Environment key mismatch"},
        413: {"description": "File exceeds tier size limit"},
        415: {"description": "Unsupported file type"},
        422: {"description": "Validation / config error"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit(RATE_LIMIT_DEFAULT, key_func=_rate_limit_identifier)
async def clean_file(
    request:          Request,
    background_tasks: BackgroundTasks,
    file:             UploadFile = File(...),
    config:           str | None = Form(default=None),
    output_format:    str | None = Form(default=None),
    dry_run:          bool       = Form(default=False),
    dedupe_all:       bool       = Form(default=False),
    x_clean_config:   str | None = Header(default=None, alias="X-Clean-Config"),
    x_webhook_url:    str | None = Header(default=None, alias="X-Webhook-URL"),
    x_output_format:  str | None = Header(default=None, alias="X-Output-Format"),
    x_dry_run:        str | None = Header(default=None, alias="X-Dry-Run"),
    x_dedupe_all:     str | None = Header(default=None, alias="X-Dedupe-All"),
    x_crypto_salt:    str | None = Header(default=None, alias="X-Crypto-Salt"),
    api_key:          APIKeyRecord = Security(verify_api_key),
) -> Response:

    request.state.api_key_tier = api_key.tier

    # ── Resolve flags ─────────────────────────────────────────────────────────
    is_dry_run    = dry_run    or (x_dry_run    or "").strip().lower() in ("1", "true", "yes")
    is_dedupe_all = dedupe_all or (x_dedupe_all or "").strip().lower() in ("1", "true", "yes")
    crypto_salt   = (x_crypto_salt or "").strip()

    # ── Start the perf clock ──────────────────────────────────────────────────
    t_start = time.perf_counter()

    # ── Read raw bytes ────────────────────────────────────────────────────────
    raw_bytes = await file.read()
    fname     = file.filename or ""

    # ── File size cap (enforced before any parsing) ───────────────────────────
    if api_key.is_test:
        max_bytes = _MAX_FILE_BYTES_TEST
        tier_label = "test"
    elif (api_key.tier or "").lower() == "pro":
        max_bytes = _MAX_FILE_BYTES_PRO
        tier_label = "pro"
    else:
        max_bytes = _MAX_FILE_BYTES_STARTER
        tier_label = "starter"

    if len(raw_bytes) > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=_error_envelope(
                "PAYLOAD_TOO_LARGE",
                f"File size {len(raw_bytes) // (1024 * 1024)} MB exceeds the "
                f"{max_mb} MB limit for the {tier_label} tier. "
                f"Compress the file or upgrade your plan.",
                _get_request_id(request),
            ),
        )

    # ── Parse ─────────────────────────────────────────────────────────────────
    sheet, file_type = parse_file(fname, raw_bytes)
    rows_in          = len(sheet)

    # ── Config ────────────────────────────────────────────────────────────────
    cfg          = resolve_config(x_clean_config, config)
    column_rules = cfg["columns"]
    resolved_fmt = (
        (output_format or x_output_format or cfg.get("output_format", "json"))
        .strip().lower()
    )
    if resolved_fmt not in {"json", "csv"}:
        resolved_fmt = "json"

    # ── DRY-RUN: validate config against headers only, return immediately ─────
    if is_dry_run:
        if not sheet:
            return JSONResponse(content={
                "dry_run": True,
                "valid": False,
                "error": "File is empty — no headers found.",
            })
        actual_columns  = set(sheet[0].keys())
        config_columns  = set(column_rules.keys())
        missing_in_file = sorted(config_columns - actual_columns)
        extra_in_file   = sorted(actual_columns - config_columns)
        mapped_columns  = sorted(actual_columns & config_columns)
        valid = len(missing_in_file) == 0

        return JSONResponse(content={
            "dry_run":          True,
            "valid":            valid,
            "file_type":        file_type,
            "total_columns":    len(actual_columns),
            "mapped_columns":   mapped_columns,
            "unmapped_columns": extra_in_file,
            "missing_columns":  missing_in_file,
            "error": (
                f"Config references {len(missing_in_file)} column(s) not found in file: "
                f"{missing_in_file}"
                if missing_in_file else None
            ),
            "rules_preview": {
                col: column_rules[col]
                for col in mapped_columns
            },
        })

    # ── Row truncation for test/sandbox keys ──────────────────────────────────
    _SANDBOX_ROW_LIMIT = 20
    truncated          = False
    original_row_count = rows_in
    if api_key.is_test and rows_in > _SANDBOX_ROW_LIMIT:
        sheet     = sheet[:_SANDBOX_ROW_LIMIT]
        truncated = True
        log.info("Row truncation: original=%d capped=%d key=%s",
                 original_row_count, _SANDBOX_ROW_LIMIT, api_key.key_prefix)

    # ── Clean — chunk-stream for Pro, single-pass for Starter/Test ───────────
    _CHUNK_SIZE = 10_000
    is_pro = (api_key.tier or "").lower() == "pro" and not api_key.is_test

    if is_pro and rows_in > _CHUNK_SIZE:
        cleaned: Sheet = []
        for i in range(0, len(sheet), _CHUNK_SIZE):
            chunk = sheet[i: i + _CHUNK_SIZE]
            cleaned.extend(clean_sheet(chunk, column_rules,
                                       dedupe_all=is_dedupe_all,
                                       crypto_salt=crypto_salt))
        # Re-run dedupe_all across chunk boundaries
        if is_dedupe_all:
            seen_g: set[tuple] = set()
            deduped_g: Sheet   = []
            for row in cleaned:
                key = tuple(str(v) for v in row.values())
                if key not in seen_g:
                    seen_g.add(key)
                    deduped_g.append(row)
            cleaned = deduped_g
    else:
        cleaned = clean_sheet(sheet, column_rules,
                              dedupe_all=is_dedupe_all,
                              crypto_salt=crypto_salt)
    sanitised = _sanitise_for_json(cleaned)
    rows_out  = len(sanitised)

    # ── Stop the clock ────────────────────────────────────────────────────────
    duration_ms = int((time.perf_counter() - t_start) * 1000)

    # ── Schedule billing ledger + audit log writes (non-blocking) ───────────
    try:
        pool = await get_pool()
        background_tasks.add_task(
            _write_billing_ledger,
            pool,
            api_key.id,           # UUID string or None for sandbox
            api_key.key_prefix,
            rows_in,
            rows_out,
            file_type,
            duration_ms,
        )
        background_tasks.add_task(
            _write_audit_log,
            pool,
            "file.clean",         # action
            True,                 # success
            # keyword args
            user_type="api_key",
            target_type="file",
            target_id=file.filename or "unknown",
            ip_address=_client_ip(request),
            details={
                "key_prefix":  api_key.key_prefix,
                "environment": api_key.environment,
                "tier":        api_key.tier,
                "file_type":   file_type,
                "rows_in":     rows_in,
                "rows_out":    rows_out,
                "duration_ms": duration_ms,
                "truncated":   truncated,
                "webhook":     bool(x_webhook_url),
                "output_format": resolved_fmt,
                "request_id":  _get_request_id(request),
            },
        )
    except HTTPException:
        pass   # DB unavailable — telemetry is non-critical; don't fail the request

    # ── Webhook mode → 202 ───────────────────────────────────────────────────
    if x_webhook_url:
        # Create job record for status polling
        job_id: str | None = None
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                job_row = await conn.fetchrow(
                    """INSERT INTO clean_jobs
                           (api_key_id, key_prefix, status, webhook_url,
                            rows_in, rows_out, file_type, duration_ms)
                       VALUES ($1,$2,'queued',$3,$4,$5,$6,$7)
                       RETURNING id""",
                    uuid.UUID(str(api_key.id)) if api_key.id else None,
                    api_key.key_prefix,
                    x_webhook_url,
                    rows_in, rows_out, file_type, duration_ms,
                )
                job_id = str(job_row["id"])
        except Exception:
            log.exception("Failed to create job record — continuing without job_id")

        background_tasks.add_task(
            _dispatch_webhook,
            x_webhook_url,
            sanitised,
            str(api_key.id) if api_key.id else None,
            api_key.key_prefix,
            job_id,
        )
        log.info("Job queued: job_id=%s rows=%d webhook=%s key=%s duration_ms=%d",
                 job_id, rows_out, x_webhook_url, api_key.key_prefix, duration_ms)
        resp: dict = {
            "status":         "queued",
            "rows_processed": rows_out,
            "duration_ms":    duration_ms,
        }
        if job_id:
            resp["job_id"]   = job_id
            resp["poll_url"] = f"/api/v1/jobs/{job_id}"
        if truncated:
            resp["rows_dropped"] = original_row_count - _SANDBOX_ROW_LIMIT
        return JSONResponse(status_code=202, content=resp)

    # ── Direct streaming mode → 200 ───────────────────────────────────────────
    if resolved_fmt == "csv":
        payload     = _to_csv_bytes(cleaned)
        media_type  = "text/csv"
        disposition = "attachment; filename=cleaned_file.csv"
    else:
        payload     = json.dumps(sanitised, ensure_ascii=False, indent=2).encode()
        media_type  = "application/json"
        disposition = "attachment; filename=cleaned_file.json"

    extra_headers: dict[str, str] = {"X-Duration-Ms": str(duration_ms)}
    if truncated:
        extra_headers["X-Rows-Truncated"] = str(original_row_count - _SANDBOX_ROW_LIMIT)

    log.info("Streaming: format=%s rows=%d size=%d key=%s duration_ms=%d",
             resolved_fmt, rows_out, len(payload), api_key.key_prefix, duration_ms)

    return StreamingResponse(
        io.BytesIO(payload),
        status_code=200,
        media_type=media_type,
        headers={"Content-Disposition": disposition, **extra_headers},
    )


# ===========================================================================
# Job status endpoint
# ===========================================================================

@router.get(
    "/jobs/{job_id}",
    summary="Poll async job status",
    responses={
        200: {"description": "Job found — returns status and metadata"},
        400: {"description": "Invalid job ID format"},
        403: {"description": "Job belongs to a different API key"},
        404: {"description": "Job not found"},
        503: {"description": "Database unavailable"},
    },
)
async def get_job_status(
    job_id:  str,
    request: Request,
    api_key: APIKeyRecord = Security(verify_api_key),
) -> JSONResponse:
    """
    Poll the status of a webhook cleaning job returned by POST /clean.

    Status lifecycle:  **queued → processing → delivered | failed**

    - `queued`      — job created, webhook dispatch not yet started
    - `processing`  — first delivery attempt in progress
    - `delivered`   — webhook accepted the payload (2xx response)
    - `failed`      — all retry attempts exhausted; check `error` field
    """
    try:
        uid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=_error_envelope("INVALID_JOB_ID",
                                   "job_id must be a valid UUID.",
                                   _get_request_id(request)),
        )

    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT id, api_key_id, key_prefix, status, webhook_url,
                          rows_in, rows_out, file_type, duration_ms,
                          error_message, created_at, updated_at
                   FROM clean_jobs WHERE id = $1""",
                uid,
            )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=_error_envelope("DB_ERROR",
                                   "Could not query job status.",
                                   _get_request_id(request)),
        ) from exc

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=_error_envelope("JOB_NOT_FOUND",
                                   f"No job found with id {job_id}.",
                                   _get_request_id(request)),
        )

    # Ownership check — job must belong to the requesting API key
    if str(row["api_key_id"]) != str(api_key.id):
        raise HTTPException(
            status_code=403,
            detail=_error_envelope("FORBIDDEN",
                                   "This job does not belong to your API key.",
                                   _get_request_id(request)),
        )

    return JSONResponse(content={
        "job_id":      str(row["id"]),
        "status":      row["status"],
        "webhook_url": row["webhook_url"],
        "rows_in":     row["rows_in"],
        "rows_out":    row["rows_out"],
        "file_type":   row["file_type"],
        "duration_ms": row["duration_ms"],
        "error":       row["error_message"],
        "created_at":  row["created_at"].isoformat(),
        "updated_at":  row["updated_at"].isoformat(),
    })


# ===========================================================================
# Health checks
# ===========================================================================

@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "version": "2.0.0"}


@router.get("/health", summary="API v1 liveness probe")
async def health_v1():
    return {"status": "ok", "version": "2.0.0", "docs": "/docs"}


# ===========================================================================
# Mount routers
# ===========================================================================

app.include_router(auth_router)
app.include_router(billing_router)
app.include_router(dash_router)
app.include_router(router)