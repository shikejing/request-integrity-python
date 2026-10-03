"""Comprehensive tests for the request integrity & anti-replay layer.

Covers: content tampering, duplicate replay, concurrent replay, clock skew,
clock rollback, key rotation, scope enforcement, malformed input, record
cleanup, and audit logging.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
from fastapi.testclient import TestClient

from integrity import Reason
from integrity.client import sign_request

from .conftest import (
    ACTIVE_KEY_ID,
    ACTIVE_SECRET,
    CALLER_A,
    CALLER_ADMIN,
    CALLER_B,
    DEPRECATED_KEY_ID,
    DEPRECATED_SECRET,
    DISABLED_KEY_ID,
    DISABLED_SECRET,
    FakeClock,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sign(
    clock: FakeClock,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    caller_id: str = CALLER_A,
    key_id: str = ACTIVE_KEY_ID,
    secret: bytes = ACTIVE_SECRET,
    timestamp: float | None = None,
    nonce: str | None = None,
    extra_headers: dict | None = None,
    query_string: str = "",
):
    return sign_request(
        method=method,
        path=path,
        query_string=query_string,
        body=body,
        caller_id=caller_id,
        key_id=key_id,
        secret=secret,
        timestamp=timestamp if timestamp is not None else clock(),
        nonce=nonce,
        extra_headers=extra_headers,
    )


def _client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Valid requests
# ---------------------------------------------------------------------------
def test_valid_get_request_accepted(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/")
    r = client.get("/", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["Hello"] == "World"
    assert body["caller"] == CALLER_A


def test_valid_post_with_body_accepted(app, clock):
    client = _client(app)
    payload = b'{"item": "book"}'
    headers = _sign(
        clock,
        method="POST",
        path="/api/orders",
        body=payload,
        extra_headers={"content-type": "application/json"},
    )
    r = client.post("/api/orders", headers=headers, content=payload)
    assert r.status_code == 200
    assert r.json()["created"] is True


def test_health_exempt(app):
    client = _client(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 2. Content tampering -> bad_signature
# ---------------------------------------------------------------------------
def test_tampered_body_rejected(app, clock):
    client = _client(app)
    signed_body = b'{"item": "book"}'
    headers = _sign(
        clock,
        method="POST",
        path="/api/orders",
        body=signed_body,
        extra_headers={"content-type": "application/json"},
    )
    # Send a different body than the one that was signed.
    r = client.post("/api/orders", headers=headers, content=b'{"item": "phone"}')
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_tampered_path_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/api/orders")
    r = client.get("/admin", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_tampered_query_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/api/orders", query_string="a=1")
    r = client.get("/api/orders?a=2", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_tampered_caller_header_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/", caller_id=CALLER_A)
    # Tamper the caller id after signing.
    headers["x-caller-id"] = CALLER_B
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_tampered_timestamp_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/", timestamp=clock())
    headers["x-timestamp"] = str(clock() + 1)
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


# ---------------------------------------------------------------------------
# 3. Key handling
# ---------------------------------------------------------------------------
def test_unknown_key_rejected(app, clock):
    client = _client(app)
    headers = _sign(
        clock, method="GET", path="/", key_id="key-unknown", secret=b"whatever"
    )
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_disabled_key_rejected(app, clock):
    client = _client(app)
    headers = _sign(
        clock,
        method="GET",
        path="/",
        key_id=DISABLED_KEY_ID,
        secret=DISABLED_SECRET,
    )
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


def test_deprecated_key_still_accepted(app, clock):
    client = _client(app)
    headers = _sign(
        clock,
        method="GET",
        path="/",
        key_id=DEPRECATED_KEY_ID,
        secret=DEPRECATED_SECRET,
    )
    r = client.get("/", headers=headers)
    assert r.status_code == 200


def test_key_rotation(app, clock):
    client = _client(app)
    keys = app.state.keys

    # Rotate: introduce a new active key; the old one becomes deprecated.
    new_key_id = "key-active-v2"
    new_secret = b"active-secret-v2"
    keys.rotate(new_key_id, new_secret)

    # New key works.
    headers = _sign(clock, method="GET", path="/", key_id=new_key_id, secret=new_secret)
    assert client.get("/", headers=headers).status_code == 200

    # Old (now deprecated) key still works during the rotation window.
    headers = _sign(
        clock,
        method="GET",
        path="/",
        key_id=ACTIVE_KEY_ID,
        secret=ACTIVE_SECRET,
    )
    assert client.get("/", headers=headers).status_code == 200

    # Disable the old key -> rejected.
    keys.disable(ACTIVE_KEY_ID)
    headers = _sign(
        clock,
        method="GET",
        path="/",
        key_id=ACTIVE_KEY_ID,
        secret=ACTIVE_SECRET,
    )
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.BAD_SIGNATURE.value


# ---------------------------------------------------------------------------
# 4. Replay detection
# ---------------------------------------------------------------------------
def test_replay_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/api/orders")
    r1 = client.get("/api/orders", headers=headers)
    r2 = client.get("/api/orders", headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert r2.json()["error"]["reason"] == Reason.REPLAY_DETECTED.value


def test_replay_with_fresh_nonce_accepted(app, clock):
    """Same content with a fresh nonce+timestamp is a new request, not a replay."""
    client = _client(app)
    h1 = _sign(clock, method="GET", path="/api/orders", nonce="nonce-1")
    clock.advance(1)
    h2 = _sign(clock, method="GET", path="/api/orders", nonce="nonce-2")
    assert client.get("/api/orders", headers=h1).status_code == 200
    assert client.get("/api/orders", headers=h2).status_code == 200


def test_replay_different_caller_accepted(app, clock):
    """The same request from a different caller is not a replay."""
    client = _client(app)
    h1 = _sign(clock, method="GET", path="/api/orders", caller_id=CALLER_A)
    h2 = _sign(clock, method="GET", path="/api/orders", caller_id=CALLER_B)
    assert client.get("/api/orders", headers=h1).status_code == 200
    assert client.get("/api/orders", headers=h2).status_code == 200


# ---------------------------------------------------------------------------
# 5. Timestamp window
# ---------------------------------------------------------------------------
def test_expired_timestamp_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/", timestamp=clock() - 301)
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.TIMESTAMP_EXPIRED.value


def test_future_timestamp_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/", timestamp=clock() + 301)
    r = client.get("/", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == Reason.TIMESTAMP_EXPIRED.value


def test_timestamp_at_boundary_accepted(app, clock):
    client = _client(app)
    # Exactly at the tolerance boundary is still accepted.
    headers = _sign(clock, method="GET", path="/", timestamp=clock() - 300)
    r = client.get("/", headers=headers)
    assert r.status_code == 200


def test_clock_rollback_replay_still_rejected(app, clock):
    """A wall-clock rollback must not cause a replay to be accepted.

    When the rollback is within the timestamp tolerance, the timestamp check
    passes and the replay store must still catch the duplicate. When the
    rollback exceeds tolerance, the timestamp check rejects it. Either way the
    replay is never accepted.
    """
    client = _client(app)
    # Accept the original request at t=1000000.
    headers = _sign(clock, method="GET", path="/api/orders")
    assert client.get("/api/orders", headers=headers).status_code == 200

    # Roll the local clock backwards by less than the tolerance so the
    # timestamp check still passes.
    clock.set(clock() - 100)

    # Replay the exact same request. The replay store must still hold the
    # record (its expiry is anchored to the request timestamp, so the rollback
    # does not prematurely evict it).
    r = client.get("/api/orders", headers=headers)
    assert r.status_code == 409
    assert r.json()["error"]["reason"] == Reason.REPLAY_DETECTED.value


# ---------------------------------------------------------------------------
# 6. Concurrency
# ---------------------------------------------------------------------------
def test_concurrent_replay_store_atomic(app, clock):
    """Directly exercise the store: concurrent duplicates -> exactly one wins."""
    store = app.state.replay_store
    fp = "a" * 64
    results = []

    def attempt():
        accepted, _ = store.check_and_add(fp, clock())
        results.append(accepted)

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(attempt) for _ in range(32)]
        for f in futures:
            f.result()

    assert sum(1 for r in results if r is True) == 1
    assert sum(1 for r in results if r is False) == 31


def test_concurrent_replay_http(app, clock):
    """Concurrent identical HTTP requests -> exactly one accepted."""
    headers = _sign(clock, method="GET", path="/api/orders")

    async def fire():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.get("/api/orders", headers=headers)

    async def run():
        return await asyncio.gather(*[fire() for _ in range(20)])

    responses = asyncio.run(run())
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 19


# ---------------------------------------------------------------------------
# 7. Scope enforcement
# ---------------------------------------------------------------------------
def test_scope_denied(app, clock):
    client = _client(app)
    # caller-b has orders:read but not orders:write.
    headers = _sign(
        clock,
        method="POST",
        path="/api/orders",
        caller_id=CALLER_B,
        body=b"{}",
        extra_headers={"content-type": "application/json"},
    )
    r = client.post("/api/orders", headers=headers, content=b"{}")
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == Reason.INSUFFICIENT_SCOPE.value


def test_scope_allowed(app, clock):
    client = _client(app)
    headers = _sign(
        clock,
        method="POST",
        path="/api/orders",
        caller_id=CALLER_A,
        body=b"{}",
        extra_headers={"content-type": "application/json"},
    )
    r = client.post("/api/orders", headers=headers, content=b"{}")
    assert r.status_code == 200


def test_admin_scope_denied(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/admin", caller_id=CALLER_A)
    r = client.get("/admin", headers=headers)
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == Reason.INSUFFICIENT_SCOPE.value


def test_admin_scope_allowed(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/admin", caller_id=CALLER_ADMIN)
    r = client.get("/admin", headers=headers)
    assert r.status_code == 200


def test_unknown_caller_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/", caller_id="caller-ghost")
    r = client.get("/", headers=headers)
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == Reason.INSUFFICIENT_SCOPE.value


# ---------------------------------------------------------------------------
# 8. Malformed input
# ---------------------------------------------------------------------------
def test_missing_headers_rejected(app):
    client = _client(app)
    r = client.get("/")
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == Reason.INVALID_REQUEST.value


def test_malformed_signature_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/")
    headers["x-signature"] = "not-hex!"
    r = client.get("/", headers=headers)
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == Reason.INVALID_REQUEST.value


def test_odd_length_signature_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/")
    headers["x-signature"] = "abc"  # odd length
    r = client.get("/", headers=headers)
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == Reason.INVALID_REQUEST.value


def test_non_numeric_timestamp_rejected(app, clock):
    client = _client(app)
    headers = _sign(clock, method="GET", path="/")
    headers["x-timestamp"] = "not-a-number"
    r = client.get("/", headers=headers)
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == Reason.INVALID_REQUEST.value


def test_body_too_large_rejected(app, clock):
    client = _client(app)
    big_body = b"x" * 1025
    headers = _sign(
        clock,
        method="POST",
        path="/api/orders",
        body=big_body,
        extra_headers={"content-type": "application/octet-stream"},
    )
    r = client.post(
        "/api/orders",
        headers=headers,
        content=big_body,
    )
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == Reason.INVALID_REQUEST.value


# ---------------------------------------------------------------------------
# 9. Record cleanup
# ---------------------------------------------------------------------------
def test_record_cleanup_removes_expired(app, clock):
    store = app.state.replay_store
    # Accept a request at t=1000000.
    headers = _sign(clock, method="GET", path="/api/orders")
    assert _client(app).get("/api/orders", headers=headers).status_code == 200
    assert len(store) == 1

    # Advance past the TTL (request_ts + ttl = 1000000 + 600).
    clock.advance(601)
    removed = store.cleanup()
    assert removed == 1
    assert len(store) == 0


def test_record_cleanup_keeps_in_window(app, clock):
    store = app.state.replay_store
    headers = _sign(clock, method="GET", path="/api/orders")
    assert _client(app).get("/api/orders", headers=headers).status_code == 200
    assert len(store) == 1

    # Advance but stay within the TTL window.
    clock.advance(300)
    removed = store.cleanup()
    assert removed == 0
    assert len(store) == 1


def test_record_cleanup_does_not_delete_still_valid_on_rollback(app, clock):
    """A clock rollback must not cause cleanup to delete in-window records."""
    store = app.state.replay_store
    headers = _sign(clock, method="GET", path="/api/orders")
    assert _client(app).get("/api/orders", headers=headers).status_code == 200

    # Roll back the clock. Cleanup must not remove the record because its
    # expiry (request_ts + ttl) is still in the future.
    clock.set(clock() - 500)
    removed = store.cleanup()
    assert removed == 0
    assert len(store) == 1


def test_store_bounded_growth(app, clock):
    """The store must not grow unbounded under sustained traffic."""
    store = app.state.replay_store
    client = _client(app)
    # Send many distinct requests across time.
    for i in range(50):
        clock.advance(1)
        headers = _sign(
            clock,
            method="GET",
            path="/api/orders",
            nonce=f"nonce-{i}",
        )
        client.get("/api/orders", headers=headers)

    # All 50 are within the 600s TTL, so all retained.
    assert len(store) == 50

    # Now advance well beyond the TTL and trigger cleanup.
    clock.advance(2000)
    store.cleanup()
    assert len(store) == 0


# ---------------------------------------------------------------------------
# 10. Audit logging
# ---------------------------------------------------------------------------
def test_audit_logs_accept_and_reject(app, clock, caplog):
    caplog.set_level(logging.INFO, logger="integrity.audit")
    client = _client(app)

    # Accept.
    headers = _sign(clock, method="GET", path="/")
    client.get("/", headers=headers)

    # Reject (replay).
    client.get("/", headers=headers)

    messages = [rec.message for rec in caplog.records]
    assert any("decision=ACCEPT" in m for m in messages)
    assert any(
        "decision=REJECT" in m and "reason=replay_detected" in m for m in messages
    )


def test_audit_logs_scope_denial(app, clock, caplog):
    caplog.set_level(logging.INFO, logger="integrity.audit")
    client = _client(app)
    headers = _sign(clock, method="GET", path="/admin", caller_id=CALLER_A)
    client.get("/admin", headers=headers)
    messages = [rec.message for rec in caplog.records]
    assert any(
        "decision=REJECT" in m and "reason=insufficient_scope" in m for m in messages
    )


def test_audit_never_contains_secret(app, clock, caplog):
    """Key material must never appear in log output."""
    caplog.set_level(logging.DEBUG, logger="integrity")
    client = _client(app)
    headers = _sign(clock, method="GET", path="/")
    client.get("/", headers=headers)
    client.get("/", headers=headers)  # replay
    client.get("/")  # invalid

    for record in caplog.records:
        assert "active-secret" not in record.message
        assert "old-secret" not in record.message
        assert "disabled-secret" not in record.message
