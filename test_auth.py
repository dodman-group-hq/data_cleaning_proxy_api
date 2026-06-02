"""
test_auth.py — API key authentication tests
Run: pytest test_auth.py -v
"""

import hashlib
import io
import json
import csv
import secrets
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import asyncpg
from fastapi.testclient import TestClient

from main import (
    app, verify_api_key, APIKeyRecord,
    _generate_raw_key, _hash_key, _KEY_PREFIX,
    TIER_RANK, router,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def _mock_pool_with_key(key_hash: str, tier: str = "pro", is_active: bool = True):
    """Return a mock asyncpg pool that returns a matching key row."""
    row = {
        "id": 42,
        "label": "Test Client",
        "tier": tier,
        "key_prefix": "dk_live_test",
        "is_active": is_active,
    }
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row if is_active else {**row, "is_active": False})
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)

    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=conn)
    return pool


def _mock_pool_no_key():
    """Return a pool that finds no matching key."""
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=None)
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=conn)
    return pool


# ---------------------------------------------------------------------------
# Unit — key generation
# ---------------------------------------------------------------------------

def test_key_has_correct_prefix():
    assert _generate_raw_key().startswith(_KEY_PREFIX)

def test_key_is_unique():
    assert _generate_raw_key() != _generate_raw_key()

def test_hash_is_deterministic():
    raw = _generate_raw_key()
    assert _hash_key(raw) == _hash_key(raw)

def test_hash_is_sha256_hex():
    h = _hash_key("test")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)

def test_hash_does_not_store_plaintext():
    raw = _generate_raw_key()
    assert raw not in _hash_key(raw)

def test_tier_rank_ordering():
    assert TIER_RANK["free"] < TIER_RANK["starter"] < TIER_RANK["pro"]


# ---------------------------------------------------------------------------
# Integration — /api/v1/clean rejects unauthenticated requests
# ---------------------------------------------------------------------------

def _clean_client():
    """A TestClient with NO dependency overrides — real auth runs."""
    # Remove any override set by other test modules
    app.dependency_overrides.pop(verify_api_key, None)
    return TestClient(app, raise_server_exceptions=False)


def test_clean_rejects_missing_token():
    """No Authorization header at all — HTTPBearer returns None → 401."""
    app.dependency_overrides.pop(verify_api_key, None)
    client = TestClient(app, raise_server_exceptions=False)
    data = make_csv([{"name": "Alice"}])
    r = client.post(
        "/api/v1/clean",
        files={"file": ("data.csv", data, "text/csv")},
        data={"config": json.dumps({"columns": {}})},
        # no Authorization header
    )
    assert r.status_code == 401
    body = r.json()
    assert body["detail"]["error"]["code"] == "INVALID_API_KEY"


def test_clean_rejects_garbage_token():
    """Valid Bearer format but unknown key — 401 (or 503 when DB absent)."""
    app.dependency_overrides.pop(verify_api_key, None)
    pool = _mock_pool_no_key()
    with patch("main.get_pool", new=AsyncMock(return_value=pool)):
        client = TestClient(app, raise_server_exceptions=False)
        data = make_csv([{"name": "Alice"}])
        r = client.post(
            "/api/v1/clean",
            files={"file": ("data.csv", data, "text/csv")},
            data={"config": json.dumps({"columns": {}})},
            headers={"Authorization": "Bearer dk_live_notarealkey"},
        )
    assert r.status_code == 401


def test_clean_rejects_malformed_auth_scheme():
    """Basic auth scheme (not Bearer) — HTTPBearer returns None → 401."""
    app.dependency_overrides.pop(verify_api_key, None)
    client = TestClient(app, raise_server_exceptions=False)
    data = make_csv([{"name": "Alice"}])
    r = client.post(
        "/api/v1/clean",
        files={"file": ("data.csv", data, "text/csv")},
        data={"config": json.dumps({"columns": {}})},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Integration — key management endpoints
# ---------------------------------------------------------------------------

def test_create_key_rejects_without_internal_secret():
    client = _clean_client()
    r = client.post(
        "/api/v1/keys",
        data={"label": "Acme Corp", "tier": "free"},
    )
    assert r.status_code in (403, 503)


def test_create_key_rejects_wrong_secret():
    client = _clean_client()
    r = client.post(
        "/api/v1/keys",
        data={"label": "Acme Corp", "tier": "free"},
        headers={"X-Internal-Secret": "wrong-secret"},
    )
    assert r.status_code in (403, 503)


def test_create_key_rejects_invalid_tier():
    """Even with correct secret, invalid tier should 422."""
    import main as m
    from main import get_pool
    secret = "test-secret-for-tier-check"
    original = m.INTERNAL_SERVICE_SECRET
    m.INTERNAL_SERVICE_SECRET = secret

    mock_conn = AsyncMock()
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=mock_conn)

    # get_pool is a FastAPI Depends — must override via dependency_overrides
    async def _mock_get_pool():
        return mock_pool

    app.dependency_overrides[get_pool] = _mock_get_pool
    try:
        client = TestClient(app, raise_server_exceptions=False)
        r = client.post(
            "/api/v1/keys",
            data={"label": "Test", "tier": "ultra"},
            headers={"X-Internal-Secret": secret},
        )
        assert r.status_code == 422
    finally:
        m.INTERNAL_SERVICE_SECRET = original
        app.dependency_overrides.pop(get_pool, None)


# ---------------------------------------------------------------------------
# Unit — verify_api_key dependency behaviour
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_verify_api_key_returns_record_for_valid_key():
    raw = _generate_raw_key()
    pool = _mock_pool_with_key(_hash_key(raw), tier="starter")

    creds = MagicMock()
    creds.credentials = raw

    with patch("main.get_pool", new=AsyncMock(return_value=pool)), \
         patch("asyncio.ensure_future"):   # patch stdlib asyncio directly
        result = await verify_api_key(credentials=creds)

    assert isinstance(result, APIKeyRecord)
    assert result.tier == "starter"   # matches tier passed to _mock_pool_with_key
    assert result.id == 42


@pytest.mark.anyio
async def test_verify_api_key_raises_401_for_unknown_key():
    from fastapi import HTTPException
    pool = _mock_pool_no_key()

    creds = MagicMock()
    creds.credentials = _generate_raw_key()

    with patch("main.get_pool", new=AsyncMock(return_value=pool)):
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key(credentials=creds)

    assert exc_info.value.status_code == 401


@pytest.mark.anyio
async def test_verify_api_key_raises_401_for_no_credentials():
    from fastapi import HTTPException
    # No pool access needed — None credentials are rejected before DB lookup

    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key(credentials=None)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Restore override for any tests that run after this module
# ---------------------------------------------------------------------------

def teardown_module(_):
    _MOCK_KEY = APIKeyRecord(id=1, label="test", tier="pro", key_prefix="dk_live_test")
    app.dependency_overrides[verify_api_key] = lambda: _MOCK_KEY