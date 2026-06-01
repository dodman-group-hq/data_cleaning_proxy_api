"""
test_main.py  –  lean test suite for the data cleaning proxy
Run:  pytest test_main.py -v
Deps: pip install pytest httpx fastapi openpyxl python-multipart
"""

import io
import json
import csv

import openpyxl
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def make_xlsx(rows: list[dict]) -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    headers = list(rows[0].keys())
    ws.append(headers)
    for row in rows:
        ws.append([row[h] for h in headers])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def post(file_bytes: bytes, config: dict, filename="data.csv"):
    return client.post(
        "/clean",
        files={"file": (filename, file_bytes, "text/csv")},
        data={"config": json.dumps(config)},
    )


def parse_response_csv(response) -> list[dict]:
    return list(csv.DictReader(io.StringIO(response.text)))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health():
    assert client.get("/health").json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_csv_parsed():
    data = make_csv([{"name": "alice", "age": "30"}])
    r = post(data, {"columns": {}, "output_format": "json"})
    assert r.status_code == 200
    assert r.json()[0]["name"] == "alice"


def test_xlsx_parsed():
    data = make_xlsx([{"name": "bob", "age": "25"}])
    r = client.post(
        "/clean",
        files={"file": ("data.xlsx", data, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"config": json.dumps({"columns": {}, "output_format": "json"})},
    )
    assert r.status_code == 200
    assert r.json()[0]["name"] == "bob"


def test_unsupported_file_type():
    r = client.post(
        "/clean",
        files={"file": ("data.txt", b"hello", "text/plain")},
        data={"config": json.dumps({"columns": {}})},
    )
    assert r.status_code == 415


# ---------------------------------------------------------------------------
# String rules
# ---------------------------------------------------------------------------

def test_strip_and_lowercase():
    data = make_csv([{"email": "  ALICE@Example.COM  "}])
    r = post(data, {"columns": {"email": ["strip", "lowercase"]}, "output_format": "json"})
    assert r.json()[0]["email"] == "alice@example.com"


def test_title_case():
    data = make_csv([{"name": "  john doe  "}])
    r = post(data, {"columns": {"name": ["strip", "title_case"]}, "output_format": "json"})
    assert r.json()[0]["name"] == "John Doe"


# ---------------------------------------------------------------------------
# Type coercion + clamp
# ---------------------------------------------------------------------------

def test_to_int_and_clamp():
    data = make_csv([{"age": "150"}, {"age": "-5"}, {"age": "25"}])
    r = post(data, {"columns": {"age": ["to_int", "clamp:0:120"]}, "output_format": "json"})
    ages = [row["age"] for row in r.json()]
    assert ages == [120, 0, 25]


def test_to_float_bad_value_becomes_null():
    data = make_csv([{"score": "abc"}])
    r = post(data, {"columns": {"score": ["to_float"]}, "output_format": "json"})
    assert r.json()[0]["score"] is None


# ---------------------------------------------------------------------------
# drop_empty
# ---------------------------------------------------------------------------

def test_drop_empty_removes_rows():
    data = make_csv([
        {"email": "a@b.com", "name": "Alice"},
        {"email": "",        "name": "Bob"},
        {"email": "c@d.com", "name": "Carol"},
    ])
    r = post(data, {"columns": {"email": ["drop_empty"]}, "output_format": "json"})
    rows = r.json()
    assert len(rows) == 2
    assert all(row["email"] != "" for row in rows)


# ---------------------------------------------------------------------------
# fill_mean / fill_value
# ---------------------------------------------------------------------------

def test_fill_mean():
    data = make_csv([{"score": "10"}, {"score": ""}, {"score": "20"}])
    r = post(data, {"columns": {"score": ["to_float", "fill_mean"]}, "output_format": "json"})
    scores = [row["score"] for row in r.json()]
    assert scores[1] == 15.0


def test_fill_value():
    data = make_csv([{"status": ""}, {"status": "active"}])
    r = post(data, {"columns": {"status": ["fill_value:unknown"]}, "output_format": "json"})
    assert r.json()[0]["status"] == "unknown"
    assert r.json()[1]["status"] == "active"


# ---------------------------------------------------------------------------
# regex rule
# ---------------------------------------------------------------------------

def test_regex_rule():
    data = make_csv([{"phone": "  +254-700-123456  "}])
    r = post(data, {"columns": {"phone": ["strip", "regex:[^0-9]:"]},"output_format": "json"})
    assert r.json()[0]["phone"] == "254700123456"


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

def test_csv_output():
    data = make_csv([{"name": "alice"}])
    r = post(data, {"columns": {}, "output_format": "csv"})
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    rows = parse_response_csv(r)
    assert rows[0]["name"] == "alice"


def test_json_output():
    data = make_csv([{"name": "alice"}])
    r = post(data, {"columns": {}, "output_format": "json"})
    assert r.status_code == 200
    assert r.json()[0]["name"] == "alice"


# ---------------------------------------------------------------------------
# Config via header (takes precedence)
# ---------------------------------------------------------------------------

def test_header_config_overrides_form():
    data = make_csv([{"email": "  BOB@TEST.COM  "}])
    header_cfg = json.dumps({"columns": {"email": ["strip", "lowercase"]}, "output_format": "json"})
    form_cfg   = json.dumps({"columns": {}, "output_format": "json"})
    r = client.post(
        "/clean",
        files={"file": ("data.csv", data, "text/csv")},
        data={"config": form_cfg},
        headers={"X-Clean-Config": header_cfg},
    )
    assert r.json()[0]["email"] == "bob@test.com"


# ---------------------------------------------------------------------------
# Invalid config
# ---------------------------------------------------------------------------

def test_invalid_json_config_returns_422():
    data = make_csv([{"name": "alice"}])
    r = client.post(
        "/clean",
        files={"file": ("data.csv", data, "text/csv")},
        data={"config": "not-valid-json"},
    )
    assert r.status_code == 422