"""Top-level request verification pipeline.

Check order (each failure has a distinct RejectionReason):
  1. structure  -> MALFORMED (missing fields, bad encoding, oversize body,
                   bad signature format)
  2. timestamp  -> TIMESTAMP_EXPIRED (too old) / TIMESTAMP_SKEW (future)
  3. key        -> KEY_UNKNOWN / KEY_REVOKED
  4. signature  -> SIGNATURE_INVALID (any content tampering lands here)
  5. scope      -> FORBIDDEN_SCOPE
  6. replay     -> REPLAY (atomic; concurrent duplicates pass at most once)

Every decision is audit-logged with reason, caller, kid and key generation;
key material and signatures are never logged.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass

from .canonicalize import canonical_request, content_digest
from .errors import RequestRejected, RejectionReason
from .keys import KeyStore
from .replay import ReplayStore

logger = logging.getLogger("request_integrity")

_SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_FIELD = 256  # sanity bound for header-ish fields


@dataclass(frozen=True)
class SignedRequest:
    caller_id: str
    scope: str
    kid: str
    timestamp: str
    nonce: str
    signature: str
    method: str
    path: str
    query: str
    body: bytes


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    caller_id: str = ""
    key_generation: int = 0


class Verifier:
    def __init__(
        self,
        keystore: KeyStore,
        replay_store: ReplayStore,
        caller_scopes: dict[str, set[str]],
        tolerance_seconds: float,
        max_body_bytes: int,
        clock=time.time,
    ) -> None:
        self._keys = keystore
        self._replay = replay_store
        self._scopes = {c: set(s) for c, s in caller_scopes.items()}
        self._tolerance = float(tolerance_seconds)
        self._max_body = int(max_body_bytes)
        self._clock = clock

    # -- individual stages -------------------------------------------------

    def _check_structure(self, req: SignedRequest) -> float:
        for name, val in (("caller_id", req.caller_id), ("scope", req.scope),
                          ("kid", req.kid), ("nonce", req.nonce),
                          ("timestamp", req.timestamp)):
            if not val or len(val) > _MAX_FIELD:
                raise RequestRejected(RejectionReason.MALFORMED,
                                      f"missing or invalid field: {name}")
        if len(req.body) > self._max_body:
            raise RequestRejected(RejectionReason.MALFORMED,
                                  "request body too large")
        if not _SIG_RE.match(req.signature or ""):
            raise RequestRejected(RejectionReason.MALFORMED,
                                  "invalid signature format")
        try:
            return float(req.timestamp)
        except (TypeError, ValueError):
            raise RequestRejected(RejectionReason.MALFORMED,
                                  "invalid timestamp") from None

    def _check_timestamp(self, ts: float, now: float) -> None:
        delta = now - ts
        if delta > self._tolerance:
            raise RequestRejected(RejectionReason.TIMESTAMP_EXPIRED,
                                  "timestamp outside tolerance window")
        if delta < -self._tolerance:
            raise RequestRejected(RejectionReason.TIMESTAMP_SKEW,
                                  "timestamp too far ahead of local clock")

    def _check_scope(self, caller_id: str, scope: str) -> None:
        granted = self._scopes.get(caller_id)
        if granted is None or scope not in granted:
            raise RequestRejected(RejectionReason.FORBIDDEN_SCOPE,
                                  "caller not granted this scope")

    # -- pipeline ------------------------------------------------------------

    def verify(self, req: SignedRequest, now: float | None = None) -> VerificationResult:
        """Run the full pipeline; raises RequestRejected on failure."""
        now = self._clock() if now is None else now
        try:
            ts = self._check_structure(req)
            self._check_timestamp(ts, now)
            key = self._keys.lookup(req.kid)
            canonical = canonical_request(req.method, req.path, req.query,
                                          req.timestamp, req.nonce, req.body)
            if not key.verify(canonical, req.signature):
                raise RequestRejected(RejectionReason.SIGNATURE_INVALID,
                                      "signature mismatch")
            self._check_scope(req.caller_id, req.scope)
            fingerprint = content_digest(req.kid.encode() + b"\n" + canonical)
            if not self._replay.check_and_record(fingerprint):
                raise RequestRejected(RejectionReason.REPLAY,
                                      "duplicate request within window")
        except RequestRejected as e:
            logger.info("request rejected: reason=%s caller=%s kid=%s",
                        e.reason.value, req.caller_id, req.kid)
            raise
        logger.info("request accepted: caller=%s kid=%s generation=%d",
                    req.caller_id, req.kid, key.generation)
        return VerificationResult(ok=True, caller_id=req.caller_id,
                                  key_generation=key.generation)
