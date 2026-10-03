"""HTTP-level tests through the FastAPI app."""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest
from fastapi.testclient import TestClient

from app.canonicalize import canonical_request
from app.config import Settings
from app.guard import build_verifier
from main import app

SECRET = b"new-secret"


@pytest.fixture()
def client():
    app.state.verifier = build_verifier(Settings(
        tolerance_seconds=300,
        replay_window_seconds=600,
        max_body_bytes=1024,
        keys={"k1": "new-secret"},
        key_generations={"k1": 1},
        revoked_kids=set(),
        caller_scopes={"alice": {"read"}},
    ))
    return TestClient(app)


def signed_headers(body: bytes, nonce: str, ts: str | None = None,
                   secret: bytes = SECRET, caller="alice", scope="read",
                   query="a=1"):
    ts = ts or str(int(time.time()))
    canon = canonical_request("POST", "/api/echo", query, ts, nonce, body)
    sig = hmac.new(secret, canon, hashlib.sha256).hexdigest()
    return {
        "X-Caller-Id": caller, "X-Scope": scope, "X-Key-Id": "k1",
        "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig,
    }


def test_root_endpoint_unchanged(client):
    r = client.get("/")
    assert r.status_code == 200 and r.json() == {"Hello": "World"}


def test_valid_request_accepted(client):
    body = b'{"msg": "hi"}'
    r = client.post("/api/echo?a=1", content=body,
                    headers=signed_headers(body, "h1"))
    assert r.status_code == 200
    assert r.json() == {"echo": '{"msg": "hi"}'}


def test_tampered_body_rejected(client):
    body = b'{"msg": "hi"}'
    headers = signed_headers(body, "h2")
    r = client.post("/api/echo?a=1", content=b'{"msg": "bye"}',
                    headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"] == "signature_invalid"


def test_replay_rejected_409(client):
    body = b'{"msg": "hi"}'
    headers = signed_headers(body, "h3")
    assert client.post("/api/echo?a=1", content=body, headers=headers).status_code == 200
    r = client.post("/api/echo?a=1", content=body, headers=headers)
    assert r.status_code == 409
    assert r.json()["detail"] == "replay_detected"


def test_missing_headers_rejected_400(client):
    r = client.post("/api/echo?a=1", content=b"{}")
    assert r.status_code == 400
    assert r.json()["detail"] == "malformed_request"


def test_forbidden_scope_rejected_403(client):
    body = b"{}"
    headers = signed_headers(body, "h4", scope="admin")
    r = client.post("/api/echo?a=1", content=body, headers=headers)
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden_scope"


def test_wrong_secret_rejected_without_leaking(client):
    body = b"{}"
    headers = signed_headers(body, "h5", secret=b"attacker-secret")
    r = client.post("/api/echo?a=1", content=body, headers=headers)
    assert r.status_code == 401
    assert "attacker-secret" not in r.text and "new-secret" not in r.text


def test_oversize_body_rejected(client):
    r = client.post("/api/echo?a=1", content=b"x" * 2000,
                    headers=signed_headers(b"x", "h6"))
    assert r.status_code == 400
