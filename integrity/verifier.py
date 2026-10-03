"""Request integrity verifier.

Orchestrates the full verification pipeline for a single request:

1. Parse and validate the integrity headers.
2. Look up the signing key (reject unknown/disabled keys).
3. Verify the HMAC signature over the canonical request.
4. Check the timestamp against the tolerated window.
5. Atomically check-and-record the request fingerprint for replay detection.
6. Check the caller's granted scopes against the route requirement.

Each failure raises a typed :class:`~integrity.errors.IntegrityError` with a
stable :class:`~integrity.errors.Reason`. Decisions are audit-logged.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from .audit import log_clock_rollback, log_decision
from .canonical import build_canonical, verify_signature
from .config import (
    HEADER_CALLER_ID,
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    IntegrityConfig,
)
from .errors import (
    BadSignatureError,
    InsufficientScopeError,
    IntegrityError,
    InvalidRequestError,
    ReplayDetectedError,
    TimestampExpiredError,
)
from .keys import KeyNotFoundError, KeyRegistry
from .replay import ReplayStore
from .replay import fingerprint as compute_fingerprint
from .scope import ScopeRegistry, UnknownCallerError


@dataclass
class VerificationResult:
    """Outcome of a successful verification."""

    caller_id: str
    key_id: str
    fingerprint: str
    request_ts: float
    scopes: frozenset[str]


@dataclass
class IntegrityHeaders:
    """Parsed integrity headers."""

    caller_id: str
    key_id: str
    timestamp: float
    nonce: str
    signature: str


class IntegrityVerifier:
    """Verifies incoming requests against the integrity policy."""

    def __init__(
        self,
        config: IntegrityConfig,
        keys: KeyRegistry,
        scopes: ScopeRegistry,
        replay_store: ReplayStore | None = None,
    ) -> None:
        self.config = config
        self.keys = keys
        self.scopes = scopes
        # NOTE: use `is not None` rather than `or` because ReplayStore defines
        # __len__ and is therefore falsy when empty.
        self.replay = (
            replay_store
            if replay_store is not None
            else ReplayStore(
                ttl_seconds=config.replay_ttl_seconds,
                cleanup_interval_seconds=config.cleanup_interval_seconds,
                max_records=config.max_replay_records,
                clock=config.clock,
            )
        )
        self._clock = config.clock
        self._last_now: float | None = None

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------
    def parse_headers(self, headers: Mapping[str, str]) -> IntegrityHeaders:
        """Extract and validate the required integrity headers.

        Raises :class:`InvalidRequestError` for missing or malformed headers.
        """

        def get(name: str) -> str | None:
            return headers.get(name)

        caller_id = get(HEADER_CALLER_ID)
        key_id = get(HEADER_KEY_ID)
        ts_raw = get(HEADER_TIMESTAMP)
        nonce = get(HEADER_NONCE)
        signature = get(HEADER_SIGNATURE)

        missing = [
            name
            for name, val in (
                (HEADER_CALLER_ID, caller_id),
                (HEADER_KEY_ID, key_id),
                (HEADER_TIMESTAMP, ts_raw),
                (HEADER_NONCE, nonce),
                (HEADER_SIGNATURE, signature),
            )
            if not val
        ]
        if missing:
            raise InvalidRequestError(
                "missing required integrity header(s): " + ", ".join(missing)
            )

        # Timestamp must be a finite number (integer or float seconds).
        try:
            timestamp = float(ts_raw)  # type: ignore[arg-type]
        except TypeError, ValueError:
            raise InvalidRequestError("timestamp header is not a number")
        if not math.isfinite(timestamp):
            raise InvalidRequestError("timestamp header is not a finite number")

        # Signature must be a hex string of even length.
        sig = signature.strip()  # type: ignore[union-attr]
        if len(sig) % 2 != 0:
            raise InvalidRequestError("signature has an invalid length")
        try:
            bytes.fromhex(sig)
        except ValueError:
            raise InvalidRequestError("signature is not valid hexadecimal")

        return IntegrityHeaders(
            caller_id=caller_id.strip(),  # type: ignore[union-attr]
            key_id=key_id.strip(),  # type: ignore[union-attr]
            timestamp=timestamp,
            nonce=nonce.strip(),  # type: ignore[union-attr]
            signature=sig,
        )

    # ------------------------------------------------------------------
    # Clock
    # ------------------------------------------------------------------
    def _now(self) -> float:
        now = self._clock()
        if self._last_now is not None and now < self._last_now:
            log_clock_rollback(self._last_now, now)
        self._last_now = now
        return now

    # ------------------------------------------------------------------
    # Main verification
    # ------------------------------------------------------------------
    def verify(
        self,
        *,
        method: str,
        path: str,
        query_string: bytes | str,
        headers: Mapping[str, str],
        body: bytes,
        required_scope: str | None = None,
    ) -> VerificationResult:
        """Verify a request end-to-end.

        Raises a typed :class:`IntegrityError` on any rejection.
        """
        try:
            parsed = self.parse_headers(headers)

            # 1. Key lookup (unknown / disabled keys rejected).
            try:
                entry = self.keys.require(parsed.key_id)
            except KeyNotFoundError:
                self._reject(
                    BadSignatureError("unknown or disabled signing key"),
                    parsed,
                    method,
                    path,
                )
                raise  # unreachable; _reject always raises

            if not entry.is_accepted:
                self._reject(
                    BadSignatureError("signing key is disabled"),
                    parsed,
                    method,
                    path,
                )

            # 2. Build canonical string and verify signature.
            canonical = build_canonical(
                method, path, query_string, headers, body, self.config.signed_headers
            )
            if not verify_signature(entry.secret, canonical, parsed.signature):
                self._reject(
                    BadSignatureError("request signature does not match"),
                    parsed,
                    method,
                    path,
                )

            # 3. Timestamp window check.
            now = self._now()
            skew = abs(now - parsed.timestamp)
            if skew > self.config.timestamp_tolerance_seconds:
                self._reject(
                    TimestampExpiredError(
                        "request timestamp is outside the allowed window"
                    ),
                    parsed,
                    method,
                    path,
                )

            # 4. Replay detection (atomic check-and-add).
            fp = compute_fingerprint(canonical)
            accepted, _record = self.replay.check_and_add(fp, parsed.timestamp)
            if not accepted:
                self._reject(
                    ReplayDetectedError("duplicate request detected"),
                    parsed,
                    method,
                    path,
                    fingerprint=fp,
                )

            # 5. Scope authorization.
            try:
                caller = self.scopes.require(parsed.caller_id)
            except UnknownCallerError:
                self._reject(
                    InsufficientScopeError("caller is not registered"),
                    parsed,
                    method,
                    path,
                    fingerprint=fp,
                )

            if not self.scopes.is_authorized(parsed.caller_id, required_scope):
                self._reject(
                    InsufficientScopeError(
                        "caller lacks the required scope for this operation"
                    ),
                    parsed,
                    method,
                    path,
                    fingerprint=fp,
                )

            log_decision(
                accepted=True,
                reason=None,
                caller_id=parsed.caller_id,
                key_id=parsed.key_id,
                fingerprint=fp,
                method=method,
                path=path,
            )
            return VerificationResult(
                caller_id=parsed.caller_id,
                key_id=parsed.key_id,
                fingerprint=fp,
                request_ts=parsed.timestamp,
                scopes=frozenset(caller.scopes),
            )

        except IntegrityError:
            # Already audit-logged via _reject; re-raise for the middleware.
            raise
        except Exception as exc:  # pragma: no cover - defensive
            # Never leak internal details to the caller.
            log_decision(
                accepted=False,
                reason=None,
                caller_id=None,
                key_id=None,
                fingerprint=None,
                method=method,
                path=path,
                detail=f"unexpected internal error: {type(exc).__name__}",
            )
            from .errors import InternalError

            raise InternalError() from exc

    def _reject(
        self,
        exc: IntegrityError,
        parsed: IntegrityHeaders,
        method: str,
        path: str,
        *,
        fingerprint: str | None = None,
    ) -> None:
        log_decision(
            accepted=False,
            reason=exc.reason,
            caller_id=parsed.caller_id,
            key_id=parsed.key_id,
            fingerprint=fingerprint,
            method=method,
            path=path,
        )
        raise exc
