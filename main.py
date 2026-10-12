"""
Dodman · Data Cleaning Proxy API  v2.0
---------------------------------------
Stateless, single-file FastAPI service — cleaned rows returned directly or
routed to a webhook.  Now includes:

  • Unified asyncpg schema (users / api_keys / billing_ledger)
  • dk_test_ / dk_live_ prefix enforcement with environment mismatch guard.
    dk_live_ requires DODMAN_ENV=production with NO override. dk_test_ in
    production is blocked by default but overridable per-user via the
    allow_test_in_production dashboard toggle.
  • Per-request cleaning summary (rows_in / rows_out / dupes_removed / status)
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

Per-user setting (stored on `users.allow_test_in_production`, default FALSE):
  Toggled via PATCH /auth/me/allow-test-in-production. When FALSE (default),
  dk_test_ keys are rejected while DODMAN_ENV=production. A user can flip it
  TRUE from their dashboard to let their own test keys run against the
  production deployment. This is one-directional: dk_live_ keys requiring
  DODMAN_ENV=production has no toggle anywhere in this file — it is always on.
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
from email_validator import validate_email, EmailNotValidError

from dodman_billing import (
    BillingConfig, BrandingConfig, Plan, PlanRegistry,
    SubscriptionRepository, PaystackClient, SharedUsersResolver,
    BillingEngine, build_billing_router,
)
from dodman_billing.notifications import ResendEmailSender

load_dotenv()
log = logging.getLogger(__name__)

log.warning("STARTUP ENV CHECK: DODMAN_ENV=%r", os.environ.get("DODMAN_ENV", "<NOT SET>"))

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

RATE_LIMIT_FREE     = os.getenv("RATE_LIMIT_FREE",       "60/hour")
RATE_LIMIT_STARTER  = os.getenv("RATE_LIMIT_STARTER",    "500/hour")
RATE_LIMIT_DEFAULT  = os.getenv("RATE_LIMIT_DEFAULT",    "60/hour")
# Risk 6 mitigation: Pro gets a generous hourly allowance but a burst cap
# per minute to prevent connection pool exhaustion from automated scripts.
# 99,999/hour stays but we also enforce a per-minute ceiling on the same key.
RATE_LIMIT_PRO_BURST = os.getenv("RATE_LIMIT_PRO_BURST", "500/minute")

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
# Monthly row quotas — enforced at the start of every /clean request.
# Sandbox / test keys share the FREE_MONTHLY_ROWS cap but are also
# hard-truncated to 20 rows per request so they rarely hit it.
# ---------------------------------------------------------------------------
_MONTHLY_ROWS_FREE    = int(os.getenv("MONTHLY_ROWS_FREE",    "10000"))     # sandbox / free
_MONTHLY_ROWS_STARTER = int(os.getenv("MONTHLY_ROWS_STARTER", "500000"))    # starter paid
_MONTHLY_ROWS_PRO     = int(os.getenv("MONTHLY_ROWS_PRO",     "5000000"))   # pro paid

# Maximum live API keys allowed per user per tier
_MAX_LIVE_KEYS_STARTER = 1
_MAX_LIVE_KEYS_PRO     = 5

# Feature gates — which tiers can use which capabilities
_TIERS_WEBHOOK         = {"starter", "pro"}   # async webhook delivery
_TIERS_ENCRYPT         = {"pro"}               # ENCRYPT / X-Crypto-Salt rule
_TIERS_DEDUPE_ALL_FULL = {"pro"}               # dedupe_all on files > threshold
_DEDUPE_ALL_ROW_LIMIT  = 10_000               # Starter can dedupe_all up to this many rows

# Concurrent webhook background tasks — prevents asyncio task pool exhaustion
# when many clients have flaky webhook endpoints.
_WEBHOOK_SEMAPHORE = asyncio.Semaphore(20)

# Risk 3 mitigation: per-key webhook concurrency cap.
# A single key with a broken endpoint must not monopolise all 20 global slots.
# Each key gets at most _WEBHOOK_MAX_CONCURRENT_PER_KEY simultaneous dispatches.
_WEBHOOK_MAX_CONCURRENT_PER_KEY = int(os.getenv("WEBHOOK_MAX_CONCURRENT_PER_KEY", "3"))
_webhook_key_semaphores: dict[str, asyncio.Semaphore] = {}


def _get_webhook_key_semaphore(key_prefix: str) -> asyncio.Semaphore:
    """Return (and lazily create) the per-key webhook semaphore."""
    if key_prefix not in _webhook_key_semaphores:
        _webhook_key_semaphores[key_prefix] = asyncio.Semaphore(_WEBHOOK_MAX_CONCURRENT_PER_KEY)
    return _webhook_key_semaphores[key_prefix]

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
    """
    Build the rate-limit bucket key.  For API calls we use the Bearer token
    so each key gets its own counter bucket.  For unauthenticated calls we
    fall back to IP.

    Risk 6: we prefix "tier:<tier>|" onto the key so _burst_limit_by_key()
    can recover the tier from the key string without a DB lookup.
    request.state.api_key_tier is set by the verify_api_key dependency before
    the limiter runs (FastAPI resolves Security() deps before the handler body,
    but the limiter decorator fires from the routing layer — to be safe we also
    check state and default to "free" if not yet set).
    """
    tier = getattr(request.state, "api_key_tier", "free") or "free"
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return f"tier:{tier}|{token}"
    return f"tier:{tier}|{get_remote_address(request)}"


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

# CORS_ALLOWED_ORIGINS: comma-separated list of allowed origins.
# Defaults to localhost only so that credentials (session cookies) are never
# sent cross-origin in production without an explicit opt-in.
# Example env value: "https://app.dodman.group,https://dodman.group"
_CORS_ORIGINS_RAW = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000")
_CORS_ORIGINS = [o.strip().rstrip("/") for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
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
_billing_engine: BillingEngine | None = None


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
    -- Risk mitigation: by default (FALSE) a dk_test_ key is rejected while
    -- DODMAN_ENV=production. Set TRUE via the dashboard toggle to let this
    -- user's test keys work against the production deployment (e.g. to debug
    -- against the one real environment). This is deliberately one-directional:
    -- dk_live_ keys ALWAYS require DODMAN_ENV=production with no override,
    -- since a live key has no legitimate reason to run outside production.
    allow_test_in_production BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
-- Idempotent column add for existing deployments
DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_env VARCHAR(8) NOT NULL DEFAULT 'test'
        CHECK (last_env IN ('test', 'live'));
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS allow_test_in_production BOOLEAN NOT NULL DEFAULT FALSE;
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
    -- email_token is required (alongside subscription_code) by Paystack's
    -- /subscription/disable and /subscription/enable endpoints. It is NOT
    -- the customer id/code -- it's a per-subscription token only present on
    -- the subscription.create webhook payload / GET /subscription response.
    paystack_email_token     VARCHAR(128) NOT NULL DEFAULT '',
    -- Reusable card authorization captured from a successful charge, used to
    -- charge upgrades/scheduled downgrades without a new checkout redirect.
    paystack_authorization_code VARCHAR(128) NOT NULL DEFAULT '',
    paystack_auth_reusable   BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Mirrored from Paystack: active | cancelled | non-renewing | attention | pending
    status              VARCHAR(20)  NOT NULL DEFAULT 'pending',

    -- Maps to your tier names: starter | pro
    plan                VARCHAR(16)  NOT NULL DEFAULT 'starter',

    -- Billing cycle dates from Paystack
    current_period_start TIMESTAMPTZ,
    current_period_end   TIMESTAMPTZ,

    -- Set when invoice.payment_failed fires; cleared on the next successful
    -- charge. Used to enforce a grace period before access is revoked.
    payment_failed_at   TIMESTAMPTZ,

    -- A scheduled plan change (downgrade) to apply at pending_change_at
    -- (normally current_period_end). Empty string = no pending change.
    pending_plan         VARCHAR(16)  NOT NULL DEFAULT '',
    pending_plan_code    VARCHAR(64)  NOT NULL DEFAULT '',
    pending_change_at    TIMESTAMPTZ,

    -- Full Paystack event payload for debugging/auditing
    last_event_data     JSONB,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX        IF NOT EXISTS idx_sub_status     ON subscriptions (status);
CREATE INDEX        IF NOT EXISTS idx_sub_paystack_id ON subscriptions (paystack_subscription_id);
-- NOTE: idx_sub_pending references pending_plan/pending_change_at which may not
-- exist yet on older deployments — it is created AFTER the migration blocks below.
-- Idempotent column adds for existing deployments
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS paystack_email_token VARCHAR(128) NOT NULL DEFAULT '';
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS paystack_authorization_code VARCHAR(128) NOT NULL DEFAULT '';
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS paystack_auth_reusable BOOLEAN NOT NULL DEFAULT FALSE;
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS payment_failed_at TIMESTAMPTZ;
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS pending_plan VARCHAR(16) NOT NULL DEFAULT '';
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS pending_plan_code VARCHAR(64) NOT NULL DEFAULT '';
EXCEPTION WHEN others THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS pending_change_at TIMESTAMPTZ;
EXCEPTION WHEN others THEN NULL; END $$;
-- Create the partial index now that the columns are guaranteed to exist.
DO $$ BEGIN
    CREATE INDEX IF NOT EXISTS idx_sub_pending ON subscriptions (pending_change_at) WHERE pending_plan != '';
EXCEPTION WHEN others THEN NULL; END $$;

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

-- ---------------------------------------------------------------------------
-- Monthly usage summary view — used by /clean quota check
-- Materialized as a plain query (no MAT VIEW needed — covered by index below).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ledger_key_ts
    ON billing_ledger (api_key_id, timestamp DESC);

-- ---------------------------------------------------------------------------
-- monthly_usage_cache  (Risk 2 mitigation — O(1) quota lookup)
-- One row per (api_key_id, month_bucket). Updated by the background ledger
-- writer so /clean quota checks never run a SUM() aggregate scan.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS monthly_usage_cache (
    api_key_id  UUID        NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    month_bucket DATE       NOT NULL,   -- first day of the month: date_trunc('month', NOW())
    rows_used   BIGINT      NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (api_key_id, month_bucket)
);
CREATE INDEX IF NOT EXISTS idx_usage_cache_key_month
    ON monthly_usage_cache (api_key_id, month_bucket DESC);

-- ---------------------------------------------------------------------------
-- TTL cleanup function — call periodically to prune old telemetry rows.
-- Retains 13 months for billing disputes; older rows are discarded.
-- Schedule via pg_cron or an external cron job:
--   SELECT prune_old_telemetry();
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION prune_old_telemetry() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM billing_ledger
    WHERE  timestamp < NOW() - INTERVAL '13 months';

    DELETE FROM audit_logs
    WHERE  timestamp < NOW() - INTERVAL '13 months';

    DELETE FROM clean_jobs
    WHERE  created_at < NOW() - INTERVAL '90 days'
    AND    status IN ('delivered', 'failed');

    DELETE FROM webhook_dead_letter
    WHERE  created_at < NOW() - INTERVAL '30 days';

    DELETE FROM password_resets
    WHERE  expires_at < NOW() - INTERVAL '7 days';

    DELETE FROM monthly_usage_cache
    WHERE  month_bucket < date_trunc('month', NOW() - INTERVAL '14 months');
END;
$$;
"""


async def _bootstrap_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(_BOOTSTRAP_SQL)
    log.info("Schema bootstrap complete.")



# ---------------------------------------------------------------------------
# Risk 1 mitigation — scheduled telemetry pruner
# Runs prune_old_telemetry() every 7 days so billing_ledger / audit_logs
# never grow unbounded. Uses a plain asyncio Task; no extra dependency needed.
# ---------------------------------------------------------------------------

_prune_task: asyncio.Task | None = None


async def _schedule_prune(pool: asyncpg.Pool) -> None:
    """
    Background coroutine: sleep 7 days, call prune_old_telemetry(), repeat.
    Logs success/failure but never propagates exceptions — crash here must
    not affect the request-handling event loop.
    """
    _PRUNE_INTERVAL_SECONDS = int(os.getenv("PRUNE_INTERVAL_SECONDS", str(7 * 24 * 60 * 60)))
    # Initial delay: 10 minutes after startup so the first boot doesn't hit
    # the DB immediately while the pool is warming up.
    await asyncio.sleep(600)
    while True:
        try:
            async with pool.acquire() as conn:
                await conn.execute("SELECT prune_old_telemetry()")
            log.info("prune_old_telemetry() completed successfully.")
        except Exception:
            log.exception("prune_old_telemetry() failed — will retry next cycle.")
        await asyncio.sleep(_PRUNE_INTERVAL_SECONDS)


_sub_reconcile_task: asyncio.Task | None = None


async def _schedule_subscription_reconcile(pool: asyncpg.Pool) -> None:
    """
    Background coroutine: every SUB_RECONCILE_INTERVAL_SECONDS (default 1h),
    1) apply scheduled downgrades whose billing period has ended, and
    2) sweep for subscriptions stuck past their payment-failure grace period
       or whose period_end has long passed with no renewal/cancel webhook
       ever arriving (a dropped-webhook safety net).

    Both halves now live in the shared dodman_billing package
    (BillingEngine.process_due_plan_changes / enforce_payment_grace_periods)
    rather than as module-level functions in this file. _billing_engine is
    set once, in _startup(), before this loop's first real iteration runs
    (there's a 300s warm-up sleep below, well after startup completes).
    """
    interval = int(os.getenv("SUB_RECONCILE_INTERVAL_SECONDS", str(60 * 60)))
    await asyncio.sleep(300)  # let the pool/app finish warming up first
    while True:
        if _billing_engine is None:
            log.warning("_schedule_subscription_reconcile: billing engine not ready yet, skipping this cycle.")
        else:
            try:
                await _billing_engine.process_due_plan_changes()
            except Exception:
                log.exception("process_due_plan_changes failed — will retry next cycle.")
            try:
                await _billing_engine.enforce_payment_grace_periods()
            except Exception:
                log.exception("enforce_payment_grace_periods failed — will retry next cycle.")
        await asyncio.sleep(interval)


@app.on_event("startup")
async def _startup() -> None:
    global _pool, _prune_task, _sub_reconcile_task, _billing_engine, billing_router
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

        # Billing engine/router need a live pool, so they're built here
        # rather than at module import time (see the comment above
        # VettEntitlementHooks). NOTE: this calls SubscriptionRepository's
        # init_schema() indirectly? No — it does not. init_schema() and the
        # one-time migrate_legacy_single_tenant_table() are run separately,
        # deliberately, NOT automatically on every startup (see the
        # migration runbook) — this just builds the engine/router assuming
        # that migration has already completed against this database.
        _billing_engine, billing_router = _build_billing(_pool)
        app.include_router(billing_router, prefix="/billing")

        # Start background pruner (Risk 1 mitigation)
        _prune_task = asyncio.create_task(_schedule_prune(_pool))
        # Start subscription lifecycle enforcement (scheduled plan changes +
        # payment-failure / missed-webhook grace period sweep)
        _sub_reconcile_task = asyncio.create_task(_schedule_subscription_reconcile(_pool))
        log.info("Database pool ready.  Billing engine ready.  Telemetry pruner scheduled every 7 days.  "
                 "Subscription reconciliation scheduled every %ds.  Docs: http://localhost:8000/docs",
                 int(os.getenv("SUB_RECONCILE_INTERVAL_SECONDS", str(60 * 60))))
    except Exception as exc:
        log.error("Failed to connect to database: %r", exc)


@app.on_event("shutdown")
async def _shutdown() -> None:
    global _prune_task, _sub_reconcile_task
    for task in (_prune_task, _sub_reconcile_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
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
    Fire-and-forget ledger insert + monthly_usage_cache upsert (Risk 2).
    Both writes happen in one connection acquire so we never leave the cache
    stale if the ledger write succeeds but the cache update fails.
    Called via BackgroundTasks — failures are logged but never propagated.
    """
    try:
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
            # Risk 2 mitigation: keep monthly_usage_cache in sync so quota
            # checks are O(1) point-lookups rather than full SUM() aggregates.
            if key_uuid is not None and rows_out > 0:
                await conn.execute(
                    """
                    INSERT INTO monthly_usage_cache (api_key_id, month_bucket, rows_used, updated_at)
                    VALUES ($1, date_trunc('month', NOW())::date, $2, NOW())
                    ON CONFLICT (api_key_id, month_bucket) DO UPDATE
                        SET rows_used  = monthly_usage_cache.rows_used + EXCLUDED.rows_used,
                            updated_at = NOW()
                    """,
                    key_uuid,
                    rows_out,
                )
    except Exception:
        log.exception("billing_ledger insert failed — non-fatal")


async def _get_monthly_rows_used(pool: asyncpg.Pool, api_key_id: str) -> int:
    """
    Return the total rows_out already billed for this api_key_id in the
    current calendar month.

    Risk 2 mitigation: reads from monthly_usage_cache (O(1) point-lookup)
    instead of running a SUM() aggregate over the full billing_ledger.
    Falls back to the aggregate query if the cache row is absent (e.g. first
    request of the month before any write has populated the cache).
    Returns 0 for sandbox keys (no DB row).
    """
    if not api_key_id:
        return 0
    try:
        key_uuid = uuid.UUID(str(api_key_id))
    except ValueError:
        return 0
    try:
        async with pool.acquire() as conn:
            # Fast path: cache hit
            cache_row = await conn.fetchrow(
                """
                SELECT rows_used
                FROM   monthly_usage_cache
                WHERE  api_key_id    = $1
                AND    month_bucket  = date_trunc('month', NOW())::date
                """,
                key_uuid,
            )
            if cache_row is not None:
                return int(cache_row["rows_used"])

            # Slow path: cache miss (first request of the month) — aggregate
            # and prime the cache so subsequent calls are fast.
            ledger_row = await conn.fetchrow(
                """
                SELECT COALESCE(SUM(rows_out), 0)::BIGINT AS total
                FROM   billing_ledger
                WHERE  api_key_id = $1
                AND    timestamp  >= date_trunc('month', NOW())
                """,
                key_uuid,
            )
            total = int(ledger_row["total"]) if ledger_row else 0
            if total > 0:
                # Seed the cache to avoid repeated aggregate scans this month
                await conn.execute(
                    """
                    INSERT INTO monthly_usage_cache (api_key_id, month_bucket, rows_used, updated_at)
                    VALUES ($1, date_trunc('month', NOW())::date, $2, NOW())
                    ON CONFLICT (api_key_id, month_bucket) DO NOTHING
                    """,
                    key_uuid,
                    total,
                )
            return total
    except Exception:
        log.exception("monthly_rows_used query failed — defaulting to 0 (non-fatal)")
        return 0



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

    dk_live_*          Live key. ALWAYS requires DODMAN_ENV=production — this is
                       a hard rule with no override, because a live key carries
                       real billing/customer data and has no legitimate reason
                       to ever run outside the actual production deployment.
                       Raises 400 INVALID_ENVIRONMENT_KEY otherwise.
    dk_test_*          Test key. Truncates upload to 20 rows. Rejected while
                       DODMAN_ENV=production UNLESS the owning user has set
                       allow_test_in_production — see below. This direction is
                       toggleable because "use my test key against the one
                       production deployment" is a normal, legitimate workflow.
    dk_sandbox_test_99 Universal open-sandbox key.  5 req/day per IP; 20-row cap.

    allow_test_in_production (per-user, dashboard-toggleable, default FALSE):
    Read from the `users` table (joined in below). Defaults to FALSE for every
    user, and for any key with no owning user (no dashboard to toggle), so
    rate limits / usage / billing stay protected from test traffic landing in
    production accounting unless a user explicitly opts in.
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

    is_live_key = raw.startswith(_PREFIX_LIVE)
    is_test_key = raw.startswith(_PREFIX_TEST)

    # ── Live key environment guard — ALWAYS enforced, never toggleable ───────
    # No per-user setting can relax this, so it's checked before the DB hit
    # (fast fail) exactly like the original prefix-only version did.
    if is_live_key and _RUNTIME_ENV() != "production":
        asyncio.ensure_future(_log_auth_failure(
            request, "auth.env_mismatch",
            f"dk_live_ key used in {_RUNTIME_ENV()} environment",
            raw[:16],
        ))
        raise HTTPException(
            status_code=400,
            detail=_error_envelope(
                "INVALID_ENVIRONMENT_KEY",
                "A dk_live_ key cannot be used outside a production environment. "
                "This rule has no override.",
                _get_request_id(request),
            ),
        )

    # ── DB validation ─────────────────────────────────────────────────────────
    # The test-key runtime guard below needs the owning user's
    # allow_test_in_production preference, so it's joined in here.
    hashed = _hash_key(raw)
    pool   = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT k.id, k.user_id, k.label, k.tier, k.key_prefix,
                   k.environment, k.is_active,
                   COALESCE(u.allow_test_in_production, FALSE) AS allow_test_in_production
            FROM   api_keys k
            LEFT JOIN users u ON u.id = k.user_id
            WHERE  k.key_hash = $1
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
    # is a data anomaly — reject it explicitly. This is a key-registration
    # integrity check, not a policy choice, so it has no toggle either.
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

    # ── Test key in production — the ONLY toggleable direction ───────────────
    if is_test_key and _RUNTIME_ENV() == "production" and not row["allow_test_in_production"]:
        asyncio.ensure_future(_log_auth_failure(
            request, "auth.env_mismatch",
            "dk_test_ key used in production environment",
            raw[:16],
        ))
        raise HTTPException(
            status_code=400,
            detail=_error_envelope(
                "INVALID_ENVIRONMENT_KEY",
                "A dk_test_ key cannot be used in a production environment. "
                "Enable 'Allow test key in production' on your dashboard if this "
                "is intentional.",
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
    """
    Returns the hourly rate-limit string for the authenticated key's tier.

    Risk 6 mitigation: Pro keys have a secondary per-minute burst cap enforced
    via _resolve_tier_burst_limit().  Both decorators are applied to /clean so
    an automated script can't saturate the connection pool even with a valid
    Pro key, while normal interactive use (well under 500 req/min) is unaffected.
    """
    tier = getattr(request.state, "api_key_tier", "free")
    return {
        "free":    RATE_LIMIT_FREE,
        "starter": RATE_LIMIT_STARTER,
        "pro":     "99999/hour",
    }.get(tier, RATE_LIMIT_DEFAULT)



def _burst_limit_by_key(key: str) -> str:
    """
    Risk 6 mitigation: per-minute burst ceiling.

    slowapi's LimitGroup.__iter__ only supports two callable signatures for
    dynamic limit providers:
      • fn()      — zero-arg
      • fn(key)   — called with key_func(request) result

    It never passes the request object directly, so we encode the tier into
    the key string inside _rate_limit_identifier (prefixed "tier:<tier>|")
    and decode it here — no extra DB round-trip needed.
    """
    # key format: "tier:pro|<token>"  /  "tier:starter|<token>"  /  plain IP
    if key.startswith("tier:"):
        tier = key.split("|", 1)[0][5:]
    else:
        tier = "free"
    return {
        "free":    "5/minute",
        "starter": "50/minute",
        "pro":     RATE_LIMIT_PRO_BURST,
    }.get(tier, "10/minute")


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
@limiter.limit("5/hour", key_func=get_remote_address)
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
        async with conn.transaction():
            # Required together, not either alone (verified directly): RLS on
            # subscriptions blocks any row unless app.current_product is set
            # on this connection first, regardless of what the JOIN's own
            # ON-clause filters for.
            await conn.execute("SELECT set_config('app.current_product', 'vett', true)")
            row = await conn.fetchrow(
                """
                SELECT u.id, u.email, u.last_env, u.allow_test_in_production, u.created_at,
                       s.status   AS sub_status,
                       s.plan     AS sub_plan,
                       s.current_period_end AS sub_period_end,
                       s.pending_plan       AS pending_plan,
                       s.pending_change_at  AS pending_change_at
                FROM   users u
                LEFT JOIN subscriptions s ON s.user_id = u.id AND s.product = 'vett'
                WHERE  u.id = $1
                """,
                uuid.UUID(user_id),
            )
    if row is None:
        raise _unauth()

    return {
        "id":                       str(row["id"]),
        "email":                    row["email"],
        "last_env":                 row["last_env"],
        "allow_test_in_production": row["allow_test_in_production"],
        "created_at":               row["created_at"],
        "sub_status":               row["sub_status"] or "none",
        "sub_plan":                 row["sub_plan"]   or "free",
        "sub_period_end":           row["sub_period_end"].isoformat() if row["sub_period_end"] else None,
        "pending_plan":             row["pending_plan"] or "",
        "pending_change_at":        row["pending_change_at"].isoformat() if row["pending_change_at"] else None,
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


# ---------------------------------------------------------------------------
# PATCH /auth/me/allow-test-in-production — dashboard toggle for the one
# direction of the test/live runtime guard in verify_api_key() that's allowed
# to be relaxed. Defaults to FALSE: dk_test_ keys are rejected while
# DODMAN_ENV=production. dk_live_ keys requiring DODMAN_ENV=production is a
# separate, permanent rule with no toggle anywhere — it is not affected by
# this setting.
# ---------------------------------------------------------------------------

@auth_router.patch("/me/allow-test-in-production", summary="Toggle whether this user's test keys work in production")
async def update_allow_test_in_production(
    request:      Request,
    current_user: dict         = Depends(get_current_user),
    pool:         asyncpg.Pool = Depends(get_pool),
) -> JSONResponse:
    body  = await request.json()
    allow = body.get("allow")
    if not isinstance(allow, bool):
        raise HTTPException(
            status_code=422,
            detail=_error_envelope(
                "VALIDATION_FAILED",
                "'allow' must be a boolean.",
                _get_request_id(request),
            ),
        )
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET allow_test_in_production = $1 WHERE id = $2",
            allow, uuid.UUID(current_user["id"]),
        )
    log.info("allow_test_in_production changed: user=%s allow=%s", current_user["id"], allow)
    asyncio.ensure_future(_write_audit_log(
        pool,
        action="user.allow_test_in_production_toggle",
        success=True,
        user_type="user",
        target_type="user",
        target_id=current_user["id"],
        ip_address=_client_ip(request),
        details={"allow_test_in_production": allow, "request_id": _get_request_id(request)},
    ))
    return JSONResponse(content={"allow_test_in_production": allow})


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

    # ── Enforce per-tier live key limit ───────────────────────────────────────
    if env == "live":
        sub_plan = current_user.get("sub_plan", "free")
        max_live = _MAX_LIVE_KEYS_PRO if sub_plan == "pro" else _MAX_LIVE_KEYS_STARTER
        async with pool.acquire() as conn:
            live_count_row = await conn.fetchrow(
                """
                SELECT COUNT(*) AS cnt FROM api_keys
                WHERE  user_id = $1 AND environment = 'live' AND is_active = TRUE
                """,
                uuid.UUID(current_user["id"]),
            )
        live_count = int(live_count_row["cnt"]) if live_count_row else 0
        if live_count >= max_live:
            raise HTTPException(
                status_code=409,
                detail=_error_envelope(
                    "KEY_LIMIT_REACHED",
                    f"Your {sub_plan} plan allows a maximum of {max_live} active live "
                    f"API key(s). Deactivate an existing key before issuing a new one, "
                    f"or upgrade to Pro for more keys.",
                    _get_request_id(request),
                ),
            )

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
# Billing / Paystack router — now backed by the shared dodman_billing
# package (github.com/dodman-group-hq/dodman-billing). This section wires
# Vett's real dependencies into it; the actual subscribe/webhook/cancel/
# upgrade/downgrade/reconciliation logic all lives in the package now, not
# here.
#
# billing_router itself is constructed inside _startup() below, not at
# import time — build_billing_router() needs a live BillingEngine, which
# needs a live asyncpg pool, which only exists once the app has actually
# started. This is the one structural change from the original file: the
# old billing_router was a module-level APIRouter built at import time.
# ===========================================================================

billing_router: APIRouter | None = None


class VettEntitlementHooks:
    """What 'this user is on plan X' means for Vett specifically: update the
    tier on their live API key. Runs inside the same transaction as the
    subscription row write, so the two can never disagree with each other."""

    async def on_activated(self, conn: asyncpg.Connection, user_id: str, plan_key: str) -> None:
        await conn.execute(
            "UPDATE api_keys SET tier = $1 WHERE user_id = $2 AND environment = 'live' AND is_active = TRUE",
            plan_key, uuid.UUID(user_id),
        )

    async def on_cancelled(self, conn: asyncpg.Connection, user_id: str) -> None:
        await conn.execute(
            "UPDATE api_keys SET is_active = FALSE WHERE user_id = $1 AND environment = 'live' AND is_active = TRUE",
            uuid.UUID(user_id),
        )


def _build_billing(pool: asyncpg.Pool) -> tuple[BillingEngine, APIRouter]:
    """Called once, from _startup(), after the pool exists."""

    async def _audit_log_adapter(event: str, success: bool, **kwargs) -> None:
        # Your real _write_audit_log takes `pool` as its first positional
        # arg; this closes over the pool so the package (which doesn't know
        # about your pool at all) can call it with just (event, success, **kw).
        await _write_audit_log(pool, event, success, **kwargs)

    config = BillingConfig(
        product_slug="vett",
        paystack_secret_key=PAYSTACK_SECRET_KEY,
        paystack_webhook_secret=PAYSTACK_WEBHOOK_SECRET,
        app_base_url=APP_BASE_URL,
        branding=BrandingConfig(
            product_display_name="Vett",
            support_email=RESEND_FROM,
        ),
        resend_api_key=RESEND_API_KEY,
        resend_from=RESEND_FROM,
    )

    plans = PlanRegistry([
        Plan(key="starter", paystack_plan_code=PAYSTACK_PLAN_STARTER, rank=1),
        Plan(key="pro", paystack_plan_code=PAYSTACK_PLAN_PRO, rank=2),
    ])

    repository = SubscriptionRepository(pool, product=config.product_slug)
    resolver = SharedUsersResolver(pool)

    engine = BillingEngine(
        config=config,
        plans=plans,
        repository=repository,
        paystack=PaystackClient(config.paystack_secret_key),
        hooks=VettEntitlementHooks(),
        resolve_user_by_email=resolver.user_id_by_email,
        resolve_email_by_user_id=resolver.email_by_user_id,
        email_sender=ResendEmailSender(config.resend_api_key, config.resend_from) if config.resend_api_key else None,
        audit_log=_audit_log_adapter,
    )

    router = build_billing_router(
        engine=engine,
        get_current_user=get_current_user,
        verify_internal_secret=verify_internal_secret,
        audit_log=_audit_log_adapter,
        error_envelope=_error_envelope,
        get_request_id=_get_request_id,
        client_ip=_client_ip,
    )

    return engine, router


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
            "pending_plan":      current_user.get("pending_plan", ""),
            "pending_change_at": current_user.get("pending_change_at"),
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

@dash_router.get("/billing", include_in_schema=False)
async def billing_redirect(status: str = ""):
    # The billing package and several API error messages point here.
    # dashboard.html reads ?billing= (success | failed) and opens the Billing tab.
    alert = {"success": "success", "failed": "failed", "error": "failed"}.get(status, "view")
    return RedirectResponse(url=f"/dashboard/?billing={alert}", status_code=303)


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


def _parse_xlsx(data: bytes, row_limit: int | None = None) -> Sheet:
    """
    Parse an XLSX file into a list of row dicts.

    Risk 4 mitigation: accepts an optional row_limit so we never materialise
    more rows than the caller can actually consume.  Uses itertools.islice on
    the openpyxl row iterator — the workbook stays in read-only streaming mode
    and rows beyond the limit are never loaded into memory.
    """
    from itertools import islice as _islice
    wb       = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws       = wb.active
    row_iter = ws.iter_rows(values_only=True)

    # Read header row first
    try:
        header_row = next(row_iter)
    except StopIteration:
        return []
    headers = [str(c) if c is not None else f"col_{i}" for i, c in enumerate(header_row)]

    # Apply row_limit via islice — never pulls more rows than needed
    data_rows = _islice(row_iter, row_limit) if (row_limit is not None and row_limit > 0) else row_iter
    return [dict(zip(headers, row)) for row in data_rows]


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


def _parse_xlsx_with_type(data: bytes, row_limit: int | None = None) -> tuple[Sheet, str]:
    """
    Synchronous XLSX parser that returns (sheet, 'xlsx').
    Designed to be called via run_in_executor so the heavy openpyxl work
    runs in a thread pool and never blocks the asyncio event loop.
    row_limit is forwarded to _parse_xlsx for memory-safe truncation (Risk 4).
    """
    return _parse_xlsx(data, row_limit=row_limit), "xlsx"


def _clean_in_chunks(
    sheet:        Sheet,
    column_rules: dict,
    dedupe_all:   bool,
    crypto_salt:  str,
    chunk_size:   int,
    stats:        dict | None = None,
) -> Sheet:
    """
    Pure-Python chunked cleaning, safe to run in a thread pool executor.
    Processes sheet in chunk_size batches then applies a global dedupe pass
    if dedupe_all is True. `stats["dupes_removed"]` accumulates duplicates
    caught both within each chunk and in the final cross-chunk pass.
    """
    cleaned: Sheet = []
    for i in range(0, len(sheet), chunk_size):
        chunk = sheet[i: i + chunk_size]
        cleaned.extend(clean_sheet(chunk, column_rules,
                                   dedupe_all=dedupe_all,
                                   crypto_salt=crypto_salt,
                                   stats=stats))
    if dedupe_all:
        rows_before_global = len(cleaned)
        seen_g: set[tuple] = set()
        deduped_g: Sheet   = []
        for row in cleaned:
            key = tuple(str(v) for v in row.values())
            if key not in seen_g:
                seen_g.add(key)
                deduped_g.append(row)
        cleaned = deduped_g
        if stats is not None:
            stats["dupes_removed"] = stats.get("dupes_removed", 0) + (rows_before_global - len(cleaned))
    return cleaned


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




def clean_phone_intl(value: Any, default_region: str = "KE") -> dict:
    """
    Normalise any international phone number to E.164 format (+254...).
    Falls back to the KE-specific cleaner for unrecognised numbers.
    default_region is used when the number has no country code prefix.
    """
    if value is None:
        return {"phone": None, "valid": False, "reason": "empty"}
    raw = str(int(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else str(value)
    raw = raw.strip()
    if not raw:
        return {"phone": None, "valid": False, "reason": "empty"}
    try:
        parsed = phonenumbers.parse(raw, default_region)
        if phonenumbers.is_valid_number(parsed):
            return {"phone": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164), "valid": True, "reason": None}
    except phonenumbers.NumberParseException:
        pass
    ke = clean_phone_ke(value)
    if ke:
        return {"phone": ke, "valid": True, "reason": None}
    return {"phone": raw, "valid": False, "reason": f"could not determine country for bare number (assumed {default_region})"}


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


def clean_email(value: Any, check_deliverability: bool = False) -> dict:
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
    raw = str(value).strip()
    if not raw:
        return {"email": None, "valid": False, "reason": "empty"}
    try:
        result = validate_email(raw, check_deliverability=check_deliverability)
        return {"email": result.normalized.lower(), "valid": True, "reason": None}
    except EmailNotValidError as e:
        return {"email": raw.lower(), "valid": False, "reason": str(e)}


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
    stats:        dict | None = None,
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
    rows_before_dedupe = len(sheet)
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

    if stats is not None:
        stats["dupes_removed"] = stats.get("dupes_removed", 0) + (rows_before_dedupe - len(sheet))

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
        200: {"description": "Cleaned file streamed directly (no webhook). Summary stats "
                              "(rows_in/rows_out/dupes_removed/status) are in the X-Rows-In, "
                              "X-Rows-Out, X-Dupes-Removed, X-Clean-Status headers, and also in "
                              "the JSON body under \"summary\" if X-Include-Summary: true was sent."},
        202: {"description": "Processing queued; payload POSTed to X-Webhook-URL. Response body "
                              "includes a \"summary\" object."},
        400: {"description": "Environment key mismatch"},
        413: {"description": "File exceeds tier size limit"},
        415: {"description": "Unsupported file type"},
        422: {"description": "Validation / config error"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit(RATE_LIMIT_DEFAULT, key_func=_rate_limit_identifier)
@limiter.limit(_burst_limit_by_key, key_func=_rate_limit_identifier)  # Risk 6: per-minute burst cap
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
    x_include_summary: str | None = Header(default=None, alias="X-Include-Summary"),
    api_key:          APIKeyRecord = Security(verify_api_key),
) -> Response:

    request.state.api_key_tier = api_key.tier

    # ── Resolve flags ─────────────────────────────────────────────────────────
    is_dry_run    = dry_run    or (x_dry_run    or "").strip().lower() in ("1", "true", "yes")
    is_dedupe_all = dedupe_all or (x_dedupe_all or "").strip().lower() in ("1", "true", "yes")
    crypto_salt   = (x_crypto_salt or "").strip()

    tier = (api_key.tier or "free").lower()

    # ── Feature gate: ENCRYPT rule ────────────────────────────────────────────
    # ENCRYPT and X-Crypto-Salt are Pro-only. Reject early so the user gets a
    # clear error rather than the salt being silently ignored.
    if crypto_salt and tier not in _TIERS_ENCRYPT:
        raise HTTPException(
            status_code=403,
            detail=_error_envelope(
                "FEATURE_NOT_AVAILABLE",
                "The ENCRYPT rule and X-Crypto-Salt header require a Pro subscription. "
                "Visit /dashboard/billing to upgrade.",
                _get_request_id(request),
            ),
        )

    # ── Feature gate: webhook mode ────────────────────────────────────────────
    if x_webhook_url and tier not in _TIERS_WEBHOOK:
        raise HTTPException(
            status_code=403,
            detail=_error_envelope(
                "FEATURE_NOT_AVAILABLE",
                "Async webhook delivery (X-Webhook-URL) requires a Starter or Pro "
                "subscription. Visit /dashboard/billing to upgrade.",
                _get_request_id(request),
            ),
        )

    # ── Start the perf clock ──────────────────────────────────────────────────
    t_start = time.perf_counter()

    # ── Read raw bytes ────────────────────────────────────────────────────────
    raw_bytes = await file.read()
    fname     = file.filename or ""

    # ── File size cap (enforced before any parsing) ───────────────────────────
    if api_key.is_test:
        max_bytes = _MAX_FILE_BYTES_TEST
        tier_label = "test"
    elif tier == "pro":
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

    # ── Parse — XLSX is CPU-heavy; run off the event loop to avoid blocking ───
    # Risk 4 mitigation: compute a safe row_limit before parsing so the XLSX
    # iterator is capped at parse time — no full-sheet materialisation for
    # files that would exceed the monthly quota anyway.
    lower_fname = fname.lower()
    if lower_fname.endswith(".xlsx"):
        # Tightest row limit we need to honour at parse time.
        if api_key.is_test or api_key.is_sandbox:
            _parse_row_limit: int | None = 20
        elif tier == "pro":
            _parse_row_limit = _MONTHLY_ROWS_PRO
        elif tier == "starter":
            _parse_row_limit = _MONTHLY_ROWS_STARTER
        else:
            _parse_row_limit = _MONTHLY_ROWS_FREE
        loop  = asyncio.get_event_loop()
        sheet, file_type = await loop.run_in_executor(
            None, lambda: _parse_xlsx_with_type(raw_bytes, row_limit=_parse_row_limit)
        )
    else:
        sheet, file_type = parse_file(fname, raw_bytes)
    rows_in = len(sheet)
    quota_trimmed = False

    # ── Monthly row quota check ───────────────────────────────────────────────
    # Sandbox / test keys use the free cap but are also hard-truncated to 20
    # rows per request, so they never realistically hit this limit.
    if not api_key.is_sandbox and api_key.id:
        try:
            pool_obj = await get_pool()
            rows_used = await _get_monthly_rows_used(pool_obj, api_key.id)
        except HTTPException:
            rows_used = 0   # DB unavailable — allow the request, log the miss

        if tier == "pro":
            monthly_cap = _MONTHLY_ROWS_PRO
        elif tier == "starter":
            monthly_cap = _MONTHLY_ROWS_STARTER
        else:
            monthly_cap = _MONTHLY_ROWS_FREE

        rows_remaining = monthly_cap - rows_used
        if rows_remaining <= 0:
            raise HTTPException(
                status_code=429,
                detail=_error_envelope(
                    "MONTHLY_QUOTA_EXCEEDED",
                    f"You have used all {monthly_cap:,} rows in your monthly allowance. "
                    f"Your quota resets at the start of next month. "
                    f"Visit /dashboard/billing to upgrade for a higher limit.",
                    _get_request_id(request),
                    {"rows_used": rows_used, "monthly_cap": monthly_cap},
                ),
            )
        # If the file would push the user over their cap, trim it rather than
        # reject entirely — they still get value and a clear warning header.
        if rows_in > rows_remaining:
            sheet         = sheet[:rows_remaining]
            rows_in       = rows_remaining
            quota_trimmed = True
            log.info(
                "Quota trim: key=%s rows_requested=%d rows_remaining=%d",
                api_key.key_prefix, len(sheet) + (rows_in - rows_remaining), rows_remaining,
            )

    # ── Config ────────────────────────────────────────────────────────────────
    cfg          = resolve_config(x_clean_config, config)
    column_rules = cfg["columns"]
    resolved_fmt = (
        (output_format or x_output_format or cfg.get("output_format", "json"))
        .strip().lower()
    )
    if resolved_fmt not in {"json", "csv"}:
        resolved_fmt = "json"

    # ── Feature gate: ENCRYPT rule in column_rules ────────────────────────────
    # Even if X-Crypto-Salt is absent, someone could pass ENCRYPT in column_rules.
    if tier not in _TIERS_ENCRYPT:
        for col, rules in column_rules.items():
            for r in rules:
                if r == "ENCRYPT" or r.startswith("ENCRYPT:"):
                    raise HTTPException(
                        status_code=403,
                        detail=_error_envelope(
                            "FEATURE_NOT_AVAILABLE",
                            "The ENCRYPT rule requires a Pro subscription. "
                            "Visit /dashboard/billing to upgrade.",
                            _get_request_id(request),
                        ),
                    )

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

    # ── Feature gate: dedupe_all ──────────────────────────────────────────────
    # Starter can run dedupe_all on files up to _DEDUPE_ALL_ROW_LIMIT rows.
    # Pro has no row-count restriction.
    if is_dedupe_all and tier not in _TIERS_DEDUPE_ALL_FULL:
        if rows_in > _DEDUPE_ALL_ROW_LIMIT:
            raise HTTPException(
                status_code=403,
                detail=_error_envelope(
                    "FEATURE_NOT_AVAILABLE",
                    f"dedupe_all on files larger than {_DEDUPE_ALL_ROW_LIMIT:,} rows "
                    f"requires a Pro subscription. Your file has {rows_in:,} rows. "
                    "Visit /dashboard/billing to upgrade.",
                    _get_request_id(request),
                ),
            )

    # ── Clean — chunk-stream for Pro, single-pass for Starter/Test ───────────
    _CHUNK_SIZE = 10_000
    is_pro_live = tier == "pro" and not api_key.is_test
    clean_stats: dict[str, int] = {}

    if is_pro_live and rows_in > _CHUNK_SIZE:
        loop = asyncio.get_event_loop()
        cleaned: Sheet = await loop.run_in_executor(
            None,
            lambda: _clean_in_chunks(sheet, column_rules, is_dedupe_all, crypto_salt,
                                      _CHUNK_SIZE, stats=clean_stats),
        )
    else:
        cleaned = clean_sheet(sheet, column_rules,
                              dedupe_all=is_dedupe_all,
                              crypto_salt=crypto_salt,
                              stats=clean_stats)
    sanitised = _sanitise_for_json(cleaned)
    rows_out  = len(sanitised)
    dupes_removed = clean_stats.get("dupes_removed", 0)

    # ── Stop the clock ────────────────────────────────────────────────────────
    duration_ms = int((time.perf_counter() - t_start) * 1000)

    # ── Per-request summary — included in every response below ───────────────
    # "partial" means the input was capped before cleaning even started
    # (sandbox/test 20-row cap, or a monthly-quota trim), so rows_in here is
    # already the post-cap count rather than the original upload size.
    summary = {
        "rows_in":       rows_in,
        "rows_out":      rows_out,
        "dupes_removed": dupes_removed,
        "status":        "partial" if (truncated or quota_trimmed) else "clean",
    }

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
                "dupes_removed": dupes_removed,
                "duration_ms": duration_ms,
                "truncated":   truncated,
                "quota_trimmed": quota_trimmed,
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

        async def _semaphored_dispatch() -> None:
            # Acquire per-key semaphore first (inner), then global (outer).
            # Order matters: always acquire narrower lock before broader one
            # to avoid deadlock.
            key_sem = _get_webhook_key_semaphore(api_key.key_prefix)
            async with key_sem:
                async with _WEBHOOK_SEMAPHORE:
                    await _dispatch_webhook(
                        x_webhook_url,
                        sanitised,
                        str(api_key.id) if api_key.id else None,
                        api_key.key_prefix,
                        job_id,
                    )

        background_tasks.add_task(_semaphored_dispatch)
        log.info("Job queued: job_id=%s rows=%d webhook=%s key=%s duration_ms=%d",
                 job_id, rows_out, x_webhook_url, api_key.key_prefix, duration_ms)
        resp_data: dict = {
            "status":         "queued",
            "rows_processed": rows_out,
            "duration_ms":    duration_ms,
            "summary":        summary,
        }
        if job_id:
            resp_data["job_id"]   = job_id
            resp_data["poll_url"] = f"/api/v1/jobs/{job_id}"
        if truncated:
            resp_data["rows_dropped"] = original_row_count - _SANDBOX_ROW_LIMIT
        return JSONResponse(status_code=202, content=resp_data)

    # ── Direct streaming mode → 200 ───────────────────────────────────────────
    # The body here is the cleaned file itself (CSV bytes or a bare JSON array)
    # so existing integrations keep working unchanged. The summary block is
    # always exposed via headers; pass X-Include-Summary: true to additionally
    # get it wrapped into the JSON body as {"summary": ..., "data": [...]}.
    include_summary = (x_include_summary or "").strip().lower() in ("1", "true", "yes")
    if resolved_fmt == "csv":
        payload     = _to_csv_bytes(cleaned)
        media_type  = "text/csv"
        disposition = "attachment; filename=cleaned_file.csv"
    else:
        body_obj    = {"summary": summary, "data": sanitised} if include_summary else sanitised
        payload     = json.dumps(body_obj, ensure_ascii=False, indent=2).encode()
        media_type  = "application/json"
        disposition = "attachment; filename=cleaned_file.json"

    extra_headers: dict[str, str] = {
        "X-Duration-Ms":     str(duration_ms),
        "X-Rows-In":         str(summary["rows_in"]),
        "X-Rows-Out":        str(summary["rows_out"]),
        "X-Dupes-Removed":   str(summary["dupes_removed"]),
        "X-Clean-Status":    summary["status"],
    }
    if truncated:
        extra_headers["X-Rows-Truncated"] = str(original_row_count - _SANDBOX_ROW_LIMIT)
    # Expose quota consumption so clients can track usage without a separate API call
    if not api_key.is_sandbox and api_key.id:
        try:
            pool_obj = await get_pool()
            _used_after = await _get_monthly_rows_used(pool_obj, api_key.id)
            if tier == "pro":
                _cap = _MONTHLY_ROWS_PRO
            elif tier == "starter":
                _cap = _MONTHLY_ROWS_STARTER
            else:
                _cap = _MONTHLY_ROWS_FREE
            extra_headers["X-Quota-Rows-Used"]      = str(_used_after + rows_out)
            extra_headers["X-Quota-Rows-Limit"]     = str(_cap)
            extra_headers["X-Quota-Rows-Remaining"]  = str(max(0, _cap - _used_after - rows_out))
        except Exception:
            pass  # Non-critical — never block the response over a header

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
app.include_router(dash_router)
app.include_router(router)