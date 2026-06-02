"""
test_webhook.py – tests for the async webhook / 202 hand-off behaviour.
Run alongside the main suite:  pytest test_main.py test_webhook.py -v
"""

import io
import json
import csv
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from fastapi.testclient import TestClient

from main import app, _dispatch_webhook

client = TestClient(app)


def make_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def post_with_webhook(file_bytes: bytes, config: dict, webhook_url: str, filename="data.csv"):
    return client.post(
        "/api/v1/clean",
        files={"file": (filename, file_bytes, "text/csv")},
        data={"config": json.dumps(config)},
        headers={"X-Webhook-URL": webhook_url},
    )


def post_sync(file_bytes: bytes, config: dict, filename="data.csv"):
    """No webhook header — original synchronous path."""
    return client.post(
        "/api/v1/clean",
        files={"file": (filename, file_bytes, "text/csv")},
        data={"config": json.dumps(config)},
    )


# ---------------------------------------------------------------------------
# 202 response shape
# ---------------------------------------------------------------------------

def test_webhook_returns_202():
    data = make_csv([{"name": "Alice"}, {"name": "Bob"}])
    r = post_with_webhook(data, {"columns": {"name": ["NAME"]}, "output_format": "json"}, "https://example.com/hook")
    assert r.status_code == 202


def test_webhook_response_body_shape():
    data = make_csv([{"name": "Alice"}, {"name": "Bob"}])
    r = post_with_webhook(data, {"columns": {}, "output_format": "json"}, "https://example.com/hook")
    body = r.json()
    assert body["status"] == "queued"
    assert body["rows_processed"] == 2


def test_webhook_rows_processed_reflects_cleaned_count():
    # drop_empty removes one row — rows_processed should reflect post-clean count
    data = make_csv([
        {"email": "a@b.com"},
        {"email": ""},          # will be dropped
        {"email": "c@d.com"},
    ])
    r = post_with_webhook(
        data,
        {"columns": {"email": ["drop_empty"]}, "output_format": "json"},
        "https://example.com/hook",
    )
    assert r.json()["rows_processed"] == 2


# ---------------------------------------------------------------------------
# Synchronous path still works (no regression)
# ---------------------------------------------------------------------------

def test_no_webhook_header_returns_200_json():
    data = make_csv([{"name": "alice"}])
    r = post_sync(data, {"columns": {"name": ["NAME"]}, "output_format": "json"})
    assert r.status_code == 200
    assert r.json()[0]["name"] == "Alice"


def test_no_webhook_header_returns_200_csv():
    data = make_csv([{"name": "alice"}])
    r = post_sync(data, {"columns": {}, "output_format": "csv"})
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


# ---------------------------------------------------------------------------
# _dispatch_webhook unit tests — mock httpx so no real network calls are made
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_dispatch_webhook_posts_payload():
    payload = [{"name": "Alice", "phone": "254712345678"}]
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("main.httpx.AsyncClient", return_value=mock_client):
        await _dispatch_webhook("https://example.com/hook", payload)

    mock_client.post.assert_awaited_once_with(
        "https://example.com/hook",
        json=payload,
        headers={"Content-Type": "application/json"},
    )


@pytest.mark.anyio
async def test_dispatch_webhook_timeout_does_not_raise():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("main.httpx.AsyncClient", return_value=mock_client):
        # Must not raise — errors are swallowed and logged
        await _dispatch_webhook("https://example.com/hook", [{"x": 1}])


@pytest.mark.anyio
async def test_dispatch_webhook_connection_error_does_not_raise():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        side_effect=httpx.RequestError("connection refused", request=MagicMock())
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("main.httpx.AsyncClient", return_value=mock_client):
        await _dispatch_webhook("https://down.example.com/hook", [])


@pytest.mark.anyio
async def test_dispatch_webhook_http_4xx_does_not_raise():
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "404", request=MagicMock(), response=mock_response
        )
    )

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("main.httpx.AsyncClient", return_value=mock_client):
        await _dispatch_webhook("https://example.com/hook", [])


@pytest.mark.anyio
async def test_dispatch_webhook_unexpected_exception_does_not_raise():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=RuntimeError("something exploded"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("main.httpx.AsyncClient", return_value=mock_client):
        await _dispatch_webhook("https://example.com/hook", [])