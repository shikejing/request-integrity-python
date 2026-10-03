"""Anti-replay store.

A request is identified by a *fingerprint* (the SHA-256 of its canonical
string). Two identical requests share a fingerprint; a repeated submission is
therefore detected as a replay.

Records are anchored to the request's own timestamp (``request_ts + ttl``), not
to the server's wall clock at receipt. This makes the store resilient to wall
clock rollback: rolling the server clock backwards moves ``now`` away from the
record's expiry, so records are never prematurely evicted by a rollback. A
forward jump past ``request_ts + ttl`` expires records, but by then the
timestamp check already rejects the request (it can only pass when
``|now - request_ts| <= tolerance``), giving defense in depth.

The store is thread-safe: the check-and-insert critical section is guarded by a
lock, so concurrent duplicates of the same fingerprint are mutually exclusive
and at most one can be accepted.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class ReplayRecord:
    """A remembered request fingerprint."""

    fingerprint: str
    request_ts: float
    first_seen: float
    expires_at: float


def fingerprint(canonical: str) -> str:
    """Return the SHA-256 hex fingerprint of a canonical string."""
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ReplayStore:
    """In-memory, TTL-bounded, thread-safe replay store."""

    def __init__(
        self,
        ttl_seconds: float = 600.0,
        cleanup_interval_seconds: float = 60.0,
        max_records: int = 1_000_000,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._cleanup_interval = cleanup_interval_seconds
        self._max_records = max_records
        self._clock = clock or time.time
        self._records: dict[str, ReplayRecord] = {}
        self._lock = threading.Lock()
        self._last_cleanup = self._clock()

    def _expiry_for(self, request_ts: float) -> float:
        # Anchor expiry to the request timestamp so wall-clock rollback cannot
        # shorten a record's life.
        return request_ts + self._ttl

    def check_and_add(
        self, fingerprint_value: str, request_ts: float
    ) -> tuple[bool, ReplayRecord | None]:
        """Atomically check for a fingerprint and insert it if absent.

        Returns ``(accepted, record)``. ``accepted`` is ``True`` only for the
        first occurrence; concurrent or subsequent duplicates return ``False``.
        """
        now = self._clock()
        with self._lock:
            existing = self._records.get(fingerprint_value)
            if existing is not None:
                return False, existing

            record = ReplayRecord(
                fingerprint=fingerprint_value,
                request_ts=request_ts,
                first_seen=now,
                expires_at=self._expiry_for(request_ts),
            )
            self._records[fingerprint_value] = record

            # Throttled lazy cleanup so the store cannot grow unbounded.
            if now - self._last_cleanup >= self._cleanup_interval:
                self._cleanup_locked(now)

            return True, record

    def contains(self, fingerprint_value: str) -> bool:
        with self._lock:
            return fingerprint_value in self._records

    def cleanup(self, now: float | None = None) -> int:
        """Remove expired records. Returns the number removed."""
        now = now if now is not None else self._clock()
        with self._lock:
            return self._cleanup_locked(now)

    def _cleanup_locked(self, now: float) -> int:
        expired = [fp for fp, rec in self._records.items() if rec.expires_at <= now]
        for fp in expired:
            del self._records[fp]
        self._last_cleanup = now

        # Hard safety cap: evict oldest first if still over the limit.
        if len(self._records) > self._max_records:
            overflow = len(self._records) - self._max_records
            oldest = sorted(self._records.items(), key=lambda kv: kv[1].first_seen)[
                :overflow
            ]
            for fp, _ in oldest:
                del self._records[fp]
            expired.extend(fp for fp, _ in oldest)

        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def stats(self) -> dict:
        with self._lock:
            return {
                "records": len(self._records),
                "ttl_seconds": self._ttl,
                "cleanup_interval_seconds": self._cleanup_interval,
                "max_records": self._max_records,
            }
