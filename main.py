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
import io
import json
import logging
import math
import re
import statistics
from typing import Any

import httpx
import openpyxl
from fastapi import APIRouter, BackgroundTasks, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

log = logging.getLogger(__name__)

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
# Types
# ---------------------------------------------------------------------------

Row = dict[str, Any]
Sheet = list[Row]

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
# Versioned router
# ---------------------------------------------------------------------------
# Routes are defined on this router and mounted by the app under a versioned
# prefix (e.g. /api/v1).  To add a v2, create a new router in a separate
# module and call app.include_router(v2_router, prefix="/api/v2").

router = APIRouter(prefix="/api/v1", tags=["v1"])


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


@router.post(
    "/clean",
    summary="Upload and clean a CSV or XLSX file",
    responses={
        200: {"description": "Cleaned file returned synchronously (CSV or JSON) — no X-Webhook-URL supplied"},
        202: {"description": "Processing queued; cleaned payload will be POSTed to X-Webhook-URL"},
        415: {"description": "Unsupported file type"},
        422: {"description": "Validation / config error"},
    },
)
async def clean_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description=".csv or .xlsx file to clean"),
    config: str | None = Form(
        default=None,
        description="JSON cleaning config (overridden by X-Clean-Config header if present)",
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
            "When present, the endpoint returns 202 immediately and POSTs the "
            "cleaned JSON array to this URL in the background."
        ),
    ),
):
    # ── Read file bytes in-memory ─────────────────────────────────────────────
    raw = await file.read()

    # ── Parse ─────────────────────────────────────────────────────────────────
    sheet = parse_file(file.filename or "", raw)

    # ── Config ────────────────────────────────────────────────────────────────
    cfg = resolve_config(x_clean_config, config)
    column_rules: dict[str, list[str]] = cfg["columns"]
    output_format: str = cfg["output_format"].lower()

    # ── Clean ─────────────────────────────────────────────────────────────────
    cleaned = clean_sheet(sheet, column_rules)
    sanitised = _sanitise_for_json(cleaned)

    # ── Webhook mode: enqueue background dispatch and return 202 immediately ──
    if x_webhook_url:
        background_tasks.add_task(_dispatch_webhook, x_webhook_url, sanitised)
        log.info(
            "Job queued: rows=%d webhook=%s", len(sanitised), x_webhook_url
        )
        return JSONResponse(
            status_code=202,
            content={"status": "queued", "rows_processed": len(sanitised)},
        )

    # ── Synchronous mode: respond directly (original behaviour) ──────────────
    if output_format == "json":
        return JSONResponse(content=sanitised)

    csv_bytes = _to_csv_bytes(cleaned)
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cleaned.csv"},
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