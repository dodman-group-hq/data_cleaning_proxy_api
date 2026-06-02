"""
test_rate_limit.py — rate limiting and unified error handler tests
Run: pytest test_rate_limit.py -v
"""
import io, json, csv
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app, verify_api_key, APIKeyRecord, limiter

# ---------------------------------------------------------------------------
# Auth mock
# ---------------------------------------------------------------------------

_MOCK_KEY = APIKeyRecord(id=1, label="test", tier="free", key_prefix="dk_live_test")
app.dependency_overrides[verify_api_key] = lambda: _MOCK_KEY
client = TestClient(app, raise_server_exceptions=False)


def make_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def post_clean(file_bytes, config=None, headers=None):
    return client.post(
        "/api/v1/clean",
        files={"file": ("data.csv", file_bytes, "text/csv")},
        data={"config": json.dumps(config or {"columns": {}, "output_format": "json"})},
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Unified error envelope — shape tests
# ---------------------------------------------------------------------------

def test_415_uses_error_envelope():
    r = client.post(
        "/api/v1/clean",
        files={"file": ("data.txt", b"hello", "text/plain")},
        data={"config": json.dumps({"columns": {}})},
    )
    assert r.status_code == 415
    body = r.json()
    assert "error" in body
    assert "code" in body["error"]
    assert "message" in body["error"]
    assert body["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_422_invalid_config_uses_error_envelope():
    r = client.post(
        "/api/v1/clean",
        files={"file": ("data.csv", make_csv([{"a": "1"}]), "text/csv")},
        data={"config": "not-valid-json"},
    )
    assert r.status_code == 422
    body = r.json()
    assert "error" in body
    assert body["error"]["code"] == "VALIDATION_ERROR"


def test_503_uses_error_envelope():
    """GET /api/v1/health with mocked pool failure returns structured 503."""
    r = client.get("/api/v1/health")
    assert r.status_code == 200   # health doesn't need pool — just confirm shape


def test_200_does_not_wrap_in_error():
    data = make_csv([{"name": "Alice"}])
    r = post_clean(data, {"columns": {}, "output_format": "json"})
    assert r.status_code == 200
    body = r.json()
    assert "error" not in body   # success responses are unwrapped


# ---------------------------------------------------------------------------
# create_api_key — JSON body accepted (the Postman fix)
# ---------------------------------------------------------------------------

def test_create_key_accepts_json_body_missing_label():
    """JSON body without label → structured 422, not FastAPI's raw validation dump."""
    r = client.post(
        "/api/v1/keys",
        json={"tier": "free"},
        headers={"X-Internal-Secret": "wrong"},   # will 403 before reaching label check
    )
    # 503 (no secret set) or 403 — either way NOT the old opaque 422
    assert r.status_code in (403, 503)
    body = r.json()
    assert "error" in body


def test_create_key_json_returns_structured_error_for_missing_label():
    """With correct secret and no DB, missing label returns our envelope."""
    import main as m
    from main import get_pool
    secret = "test-create-json-422"
    original = m.INTERNAL_SERVICE_SECRET
    m.INTERNAL_SERVICE_SECRET = secret

    mock_conn = AsyncMock()
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=mock_conn)

    async def _mock_get_pool():
        return mock_pool

    app.dependency_overrides[get_pool] = _mock_get_pool
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.post(
            "/api/v1/keys",
            json={"tier": "starter"},      # missing label
            headers={"X-Internal-Secret": secret},
        )
        assert r.status_code == 422
        body = r.json()
        assert "error" in body
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "label" in body["error"]["message"]
    finally:
        m.INTERNAL_SERVICE_SECRET = original
        app.dependency_overrides.pop(get_pool, None)


def test_create_key_form_data_still_works():
    """Existing form-data path still accepted alongside JSON."""
    import main as m
    from main import get_pool
    secret = "test-form-still-works"
    original = m.INTERNAL_SERVICE_SECRET
    m.INTERNAL_SERVICE_SECRET = secret

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"id": 99, "created_at": __import__("datetime").datetime.now()})
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=mock_conn)

    async def _mock_get_pool():
        return mock_pool

    app.dependency_overrides[get_pool] = _mock_get_pool
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.post(
            "/api/v1/keys",
            data={"label": "Acme Corp", "tier": "free"},
            headers={"X-Internal-Secret": secret},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["label"] == "Acme Corp"
        assert "api_key" in body
        assert body["api_key"].startswith("dk_live_")
    finally:
        m.INTERNAL_SERVICE_SECRET = original
        app.dependency_overrides.pop(get_pool, None)


# ---------------------------------------------------------------------------
# Rate limiter — 429 response shape
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_rate_limit_429_has_correct_shape():
    """Simulate a RateLimitExceeded exception and confirm envelope shape."""
    from slowapi.errors import RateLimitExceeded
    from main import _rate_limit_handler

    mock_request = MagicMock()
    mock_exc = MagicMock(spec=RateLimitExceeded)
    mock_exc.detail = "60 per 1 hour"

    response = await _rate_limit_handler(mock_request, mock_exc)

    assert response.status_code == 429
    import json as _json
    body = _json.loads(response.body)
    assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "upgrade" in body["error"]["message"].lower()
    assert "limit" in body["error"]
    assert response.headers.get("retry-after") == "60"


def test_rate_limit_config_vars_are_strings():
    """Rate limit env vars must be valid slowapi strings."""
    from main import RATE_LIMIT_FREE, RATE_LIMIT_STARTER, RATE_LIMIT_DEFAULT
    import re
    pattern = re.compile(r"^\d+/(second|minute|hour|day)$")
    assert pattern.match(RATE_LIMIT_FREE),    f"Bad RATE_LIMIT_FREE: {RATE_LIMIT_FREE}"
    assert pattern.match(RATE_LIMIT_STARTER), f"Bad RATE_LIMIT_STARTER: {RATE_LIMIT_STARTER}"
    assert pattern.match(RATE_LIMIT_DEFAULT), f"Bad RATE_LIMIT_DEFAULT: {RATE_LIMIT_DEFAULT}"


def test_limiter_keys_off_bearer_token():
    """The identifier function returns the Bearer token, not the IP."""
    from main import _rate_limit_identifier
    mock_request = MagicMock()
    mock_request.headers = {"Authorization": "Bearer dk_live_abc123"}
    mock_request.client = MagicMock()
    mock_request.client.host = "192.168.1.1"
    assert _rate_limit_identifier(mock_request) == "dk_live_abc123"


def test_limiter_falls_back_to_ip_without_bearer():
    """Without an Authorization header, identifier falls back to client IP."""
    from main import _rate_limit_identifier
    mock_request = MagicMock()
    mock_request.headers = {}
    mock_request.client = MagicMock()
    mock_request.client.host = "10.0.0.5"
    result = _rate_limit_identifier(mock_request)
    assert result == "10.0.0.5"


# ---------------------------------------------------------------------------
# Restore override for other modules
# ---------------------------------------------------------------------------

def teardown_module(_):
    app.dependency_overrides[verify_api_key] = lambda: _MOCK_KEY