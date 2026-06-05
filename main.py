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

import asyncpg
import httpx
import openpyxl
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
# Key-prefix constants
# ---------------------------------------------------------------------------

_PREFIX_LIVE     = "dk_live_"
_PREFIX_TEST     = "dk_test_"
_SANDBOX_KEY     = "dk_sandbox_test_99"        # legacy open-sandbox key
_KEY_BYTES       = 32                           # 256 bits entropy

_SANDBOX_MAX_HITS = 5
_SANDBOX_RATE     = "5/day"

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
        raise _UNAUTH

    # ── Secondary environment guard: key's stored environment vs request key ──
    # A key stored as environment='test' that physically has a dk_live_ prefix
    # is a data anomaly — reject it explicitly.
    stored_env = row["environment"]
    if raw.startswith(_PREFIX_LIVE) and stored_env != "live":
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
        raise _INVALID
    if not _verify_password(body.password, row["password_hash"]):
        raise _INVALID

    user_id = str(row["id"])
    token   = _make_session_token(user_id)

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
async def logout() -> Response:
    resp = RedirectResponse(url="/auth/login-page", status_code=303)
    # Delete the session cookie
    resp.delete_cookie(
        key="dodman_session",
        httponly=True,
        samesite="lax",
    )
    # Instruct every cache layer (browser, CDN, proxy) never to store this
    # page so the back-button cannot replay a stale authenticated view.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
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
            "SELECT id, email, last_env, created_at FROM users WHERE id = $1",
            uuid.UUID(user_id),
        )
    if row is None:
        raise _unauth()

    return {
        "id":         str(row["id"]),
        "email":      row["email"],
        "last_env":   row["last_env"],
        "created_at": row["created_at"],
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
    key_id: str,
    _:      None = Depends(verify_internal_secret),
    pool:   asyncpg.Pool = Depends(get_pool),
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
    return JSONResponse(content={"id": key_id, "is_active": False})


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

    resp = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":         current_user,
            "default_env":  current_user.get("last_env", "test"),
            "api_keys":     [_serialise_key(k) for k in keys],
            "ledger_test":  [_serialise_ledger(r) for r in ledger_test_rows],
            "ledger_live":  [_serialise_ledger(r) for r in ledger_live_rows],
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

def _parse_csv(data: bytes) -> Sheet:
    text   = data.decode("utf-8-sig")
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
        return _parse_csv(data), "csv"
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


_TYPED_RULES = {"PHONE", "NAME", "DATE"}


def apply_typed_rule(rule: str, value: Any) -> Any:
    if rule == "PHONE":  return clean_phone_ke(value)
    if rule == "NAME":   return clean_name(value)
    if rule == "DATE":   return clean_date(value)
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


def process_row(row: Row, column_rules: dict[str, list[str]]) -> Row:
    out: Row = {}
    for col, value in row.items():
        rules = column_rules.get(col)
        if rules is None:
            out[col] = str(value).strip() if value is not None else value
        else:
            current = value
            for rule in rules:
                if rule in _TYPED_RULES:
                    current = apply_typed_rule(rule, current)
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


def clean_sheet(sheet: Sheet, column_rules: dict[str, list[str]]) -> Sheet:
    stat_rules = {"fill_mean", "fill_median"}
    rules_pass1 = {
        col: [r for r in rules if r not in stat_rules]
        for col, rules in column_rules.items()
    }
    sheet = [process_row(row, rules_pass1) for row in sheet]
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
# Webhook dispatcher
# ===========================================================================

async def _dispatch_webhook(url: str, payload: list[Row]) -> None:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload,
                                         headers={"Content-Type": "application/json"})
            response.raise_for_status()
            log.info("Webhook delivered: url=%s status=%s rows=%d",
                     url, response.status_code, len(payload))
    except httpx.TimeoutException:
        log.error("Webhook timed out: url=%s", url)
    except httpx.HTTPStatusError as exc:
        log.error("Webhook rejected: url=%s status=%s", url, exc.response.status_code)
    except Exception as exc:
        log.exception("Webhook error: url=%s error=%r", url, exc)


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
        415: {"description": "Unsupported file type"},
        422: {"description": "Validation / config error"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit(RATE_LIMIT_DEFAULT, key_func=_rate_limit_identifier)
async def clean_file(
    request:         Request,
    background_tasks: BackgroundTasks,
    file:            UploadFile = File(...),
    config:          str | None = Form(default=None),
    output_format:   str | None = Form(default=None),
    x_clean_config:  str | None = Header(default=None, alias="X-Clean-Config"),
    x_webhook_url:   str | None = Header(default=None, alias="X-Webhook-URL"),
    x_output_format: str | None = Header(default=None, alias="X-Output-Format"),
    api_key:         APIKeyRecord = Security(verify_api_key),
) -> Response:

    request.state.api_key_tier = api_key.tier

    # ── Start the perf clock ──────────────────────────────────────────────────
    t_start = time.perf_counter()

    # ── Read + parse ──────────────────────────────────────────────────────────
    raw_bytes           = await file.read()
    sheet, file_type    = parse_file(file.filename or "", raw_bytes)
    rows_in             = len(sheet)

    # ── Row truncation for test/sandbox keys ──────────────────────────────────
    _SANDBOX_ROW_LIMIT = 20
    truncated          = False
    original_row_count = rows_in
    if api_key.is_test and rows_in > _SANDBOX_ROW_LIMIT:
        sheet     = sheet[:_SANDBOX_ROW_LIMIT]
        truncated = True
        log.info("Row truncation: original=%d capped=%d key=%s",
                 original_row_count, _SANDBOX_ROW_LIMIT, api_key.key_prefix)

    # ── Config ────────────────────────────────────────────────────────────────
    cfg          = resolve_config(x_clean_config, config)
    column_rules = cfg["columns"]
    resolved_fmt = (
        (output_format or x_output_format or cfg.get("output_format", "json"))
        .strip().lower()
    )
    if resolved_fmt not in {"json", "csv"}:
        resolved_fmt = "json"

    # ── Clean ─────────────────────────────────────────────────────────────────
    cleaned   = clean_sheet(sheet, column_rules)
    sanitised = _sanitise_for_json(cleaned)
    rows_out  = len(sanitised)

    # ── Stop the clock ────────────────────────────────────────────────────────
    duration_ms = int((time.perf_counter() - t_start) * 1000)

    # ── Schedule billing ledger write (non-blocking) ──────────────────────────
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
    except HTTPException:
        pass   # DB unavailable — telemetry is non-critical; don't fail the request

    # ── Webhook mode → 202 ───────────────────────────────────────────────────
    if x_webhook_url:
        background_tasks.add_task(_dispatch_webhook, x_webhook_url, sanitised)
        log.info("Job queued: rows=%d webhook=%s key=%s truncated=%s duration_ms=%d",
                 rows_out, x_webhook_url, api_key.key_prefix, truncated, duration_ms)
        return JSONResponse(
            status_code=202,
            content={
                "status":         "queued",
                "rows_processed": rows_out,
                "duration_ms":    duration_ms,
                **({"rows_dropped": original_row_count - _SANDBOX_ROW_LIMIT} if truncated else {}),
            },
        )

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