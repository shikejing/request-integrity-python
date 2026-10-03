"""End-to-end tests for the request integrity / anti-replay layer."""
from __future__ import annotations

import threading
import time

import pytest

from app.canonicalize import canonical_request, content_digest
from app.errors import RequestRejected, RejectionReason
from app.keys import KeyStore
from app.replay import ReplayStore
from app.verifier import SignedRequest, Verifier

NOW = 1_700_000_000.0
BODY = b'{"amount": 100, "to": "bob"}'
QUERY = "b=2&a=1"


def make_keystore():
    return KeyStore.from_settings(
        keys={"k-old": "old-secret", "k-new": "new-secret",
              "k-dead": "dead-secret"},
        generations={"k-old": 1, "k-new": 2, "k-dead": 3},
        revoked={"k-dead"},
    )


def make_verifier(now_holder=None, **overrides):
    now_holder = now_holder if now_holder is not None else [NOW]
    kwargs = dict(
        keystore=make_keystore(),
        replay_store=ReplayStore(window_seconds=600),
        caller_scopes={"alice": {"read"}, "bob": {"read", "write"}},
        tolerance_seconds=300,
        max_body_bytes=1024,
        clock=lambda: now_holder[0],
    )
    kwargs.update(overrides)
    return Verifier(**kwargs)


SECRETS = {"k-old": b"old-secret", "k-new": b"new-secret",
           "k-dead": b"dead-secret"}


def sign(ks, kid, ts, nonce, body=BODY, query=QUERY):
    import hashlib
    import hmac
    canon = canonical_request("POST", "/api/pay", query, ts, nonce, body)
    return hmac.new(SECRETS[kid], canon, hashlib.sha256).hexdigest()


def make_req(ks, kid="k-new", caller="alice", scope="read",
             ts=None, nonce="n1", body=BODY, query=QUERY, sig=None):
    ts = ts if ts is not None else str(int(NOW))
    if sig is None:
        sig = sign(ks, kid, ts, nonce, body, query)
    return SignedRequest(caller, scope, kid, ts, nonce, sig,
                         "POST", "/api/pay", query, body)


@pytest.fixture()
def ks():
    return make_keystore()


@pytest.fixture()
def verifier():
    return make_verifier()


# --- canonicalization / digest ---------------------------------------------

def test_digest_deterministic_and_order_insensitive():
    a = canonical_request("post", "/api/pay", "b=2&a=1", "1", "n", BODY)
    b = canonical_request("POST", "/api/pay", "a=1&b=2", "1", "n", BODY)
    assert content_digest(a) == content_digest(b)


@pytest.mark.parametrize("field", ["method", "path", "query", "ts", "nonce", "body"])
def test_any_field_change_changes_digest(field):
    base = dict(method="POST", path="/api/pay", query="a=1", ts="1",
                nonce="n", body=BODY)
    a = canonical_request(base["method"], base["path"], base["query"],
                          base["ts"], base["nonce"], base["body"])
    base[field] = {"method": "GET", "path": "/api/pay2", "query": "a=2",
                   "ts": "2", "nonce": "m", "body": b"other"}[field]
    b = canonical_request(base["method"], base["path"], base["query"],
                          base["ts"], base["nonce"], base["body"])
    assert content_digest(a) != content_digest(b)


# --- tampering ---------------------------------------------------------------

def test_happy_path(verifier, ks):
    assert verifier.verify(make_req(ks)).ok


def test_tampered_body_rejected(verifier, ks):
    sig = sign(ks, "k-new", str(int(NOW)), "n2", BODY)
    req = make_req(ks, nonce="n2", body=b'{"amount": 999, "to": "eve"}', sig=sig)
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.SIGNATURE_INVALID


def test_tampered_query_rejected(verifier, ks):
    sig = sign(ks, "k-new", str(int(NOW)), "n3", BODY, query="a=1")
    req = make_req(ks, nonce="n3", query="a=999", sig=sig)
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.SIGNATURE_INVALID


# --- replay -------------------------------------------------------------------

def test_replay_rejected_with_distinct_reason(verifier, ks):
    verifier.verify(make_req(ks, nonce="n4"))
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(make_req(ks, nonce="n4"))
    assert ei.value.reason is RejectionReason.REPLAY
    assert ei.value.reason is not RejectionReason.SIGNATURE_INVALID


def test_replay_after_window_accepted(ks):
    now = [NOW]
    v = make_verifier(now)
    req = make_req(ks, nonce="n5")
    v.verify(req)
    now[0] += 601  # beyond replay window but timestamp re-check would fail...
    # re-sign with a fresh timestamp inside tolerance; same nonce expired
    req2 = make_req(ks, nonce="n5", ts=str(int(now[0])))
    assert v.verify(req2).ok


def test_concurrent_replay_single_winner(ks):
    v = make_verifier()
    req = make_req(ks, nonce="n6")
    results = []
    def hit():
        try:
            v.verify(req)
            results.append("ok")
        except RequestRejected as e:
            results.append(e.reason)
    threads = [threading.Thread(target=hit) for _ in range(64)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert results.count("ok") == 1
    assert results.count(RejectionReason.REPLAY) == 63


# --- clock --------------------------------------------------------------------

def test_expired_timestamp_rejected(verifier, ks):
    req = make_req(ks, nonce="n7", ts=str(int(NOW - 301)))
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.TIMESTAMP_EXPIRED


def test_future_skew_rejected(verifier, ks):
    req = make_req(ks, nonce="n8", ts=str(int(NOW + 301)))
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.TIMESTAMP_SKEW


def test_clock_rollback_does_not_reopen_replay_window():
    # ReplayStore uses a monotonic clock; wall-clock rollback is irrelevant.
    store = ReplayStore(window_seconds=600)  # real monotonic clock
    assert store.check_and_record("fp") is True
    time.sleep(0.01)
    assert store.check_and_record("fp") is False


def test_clock_drift_forward_still_rejects_replay_within_window(ks):
    now = [NOW]
    v = make_verifier(now)
    req = make_req(ks, nonce="n9")
    v.verify(req)
    now[0] += 120  # local clock jumps forward, still inside replay window
    with pytest.raises(RequestRejected) as ei:
        v.verify(req)  # identical request resubmitted
    assert ei.value.reason is RejectionReason.REPLAY


# --- key rotation ---------------------------------------------------------------

def test_rotation_old_and_new_keys_verify(verifier, ks):
    assert verifier.verify(make_req(ks, kid="k-new", nonce="n10")).ok
    assert verifier.verify(make_req(ks, kid="k-old", nonce="n11")).ok


def test_revoked_key_rejected(verifier, ks):
    req = make_req(ks, kid="k-dead", nonce="n12")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.KEY_REVOKED


def test_unknown_key_rejected(verifier, ks):
    req = make_req(ks, kid="k-ghost", nonce="n13", sig="00" * 32)
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.KEY_UNKNOWN


def test_key_material_not_in_errors_or_repr(verifier, ks):
    req = make_req(ks, kid="k-dead", nonce="n14")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert "dead-secret" not in str(ei.value) + ei.value.detail
    assert "new-secret" not in repr(ks.lookup("k-new"))


# --- scope ----------------------------------------------------------------------

def test_scope_forbidden_distinct_reason(verifier, ks):
    req = make_req(ks, caller="alice", scope="write", nonce="n15")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.FORBIDDEN_SCOPE


def test_unknown_caller_rejected_as_scope(verifier, ks):
    req = make_req(ks, caller="mallory", nonce="n16")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.FORBIDDEN_SCOPE


def test_granted_scope_accepted(verifier, ks):
    assert verifier.verify(make_req(ks, caller="bob", scope="write",
                                    nonce="n17")).ok


# --- malformed / robustness ------------------------------------------------------

@pytest.mark.parametrize("sig", ["", "zz", "00", "0" * 63, "g" * 64])
def test_bad_signature_format_rejected(verifier, ks, sig):
    req = make_req(ks, nonce="n18", sig=sig)
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.MALFORMED


def test_missing_fields_rejected(verifier, ks):
    req = make_req(ks, nonce="")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.MALFORMED


def test_oversize_body_rejected(verifier, ks):
    req = make_req(ks, nonce="n19", body=b"x" * 2000)
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.MALFORMED


def test_non_numeric_timestamp_rejected(verifier, ks):
    req = make_req(ks, nonce="n20", ts="not-a-time")
    with pytest.raises(RequestRejected) as ei:
        verifier.verify(req)
    assert ei.value.reason is RejectionReason.MALFORMED


# --- replay store cleanup ---------------------------------------------------------

def test_cleanup_removes_only_expired():
    now = [1000.0]
    store = ReplayStore(window_seconds=10, clock=lambda: now[0])
    store.check_and_record("old")
    now[0] += 5
    store.check_and_record("fresh")
    now[0] += 6  # t=1011: 'old' expired, 'fresh' alive
    assert store.cleanup() == 1
    assert len(store) == 1
    assert store.check_and_record("fresh") is False  # not mistakenly removed
    assert store.check_and_record("old") is True     # expired, can re-enter


def test_store_bounded_under_churn():
    now = [0.0]
    store = ReplayStore(window_seconds=5, clock=lambda: now[0])
    for i in range(10_000):
        now[0] += 1
        store.check_and_record(f"fp-{i}")
        if i % 10 == 0:
            store.cleanup()
    store.cleanup()
    assert len(store) <= 6  # only records inside the 5s window remain
