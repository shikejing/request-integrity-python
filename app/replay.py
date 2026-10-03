"""Thread-safe replay detection with window-based cleanup.

A fingerprint is accepted only the first time it is seen within the
configured window. check_and_record is atomic under a lock, so concurrent
duplicates cannot both pass. Expiry uses a monotonic clock: a local wall
clock rollback or drift cannot reopen the window for old fingerprints.
Records expire after the window and are removed by cleanup(), so memory
stays bounded during long runs; cleanup never removes records still inside
their window.
"""
from __future__ import annotations

import threading
import time


class ReplayStore:
    def __init__(self, window_seconds: float,
                 clock=time.monotonic) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._window = float(window_seconds)
        self._clock = clock
        self._seen: dict[str, float] = {}  # fingerprint -> monotonic expiry
        self._lock = threading.Lock()

    def check_and_record(self, fingerprint: str) -> bool:
        """Atomically record fingerprint; True if new, False if replay."""
        now = self._clock()
        with self._lock:
            expiry = self._seen.get(fingerprint)
            if expiry is not None and expiry > now:
                return False
            self._seen[fingerprint] = now + self._window
            return True

    def cleanup(self) -> int:
        """Drop expired records; returns number removed."""
        now = self._clock()
        with self._lock:
            expired = [fp for fp, exp in self._seen.items() if exp <= now]
            for fp in expired:
                del self._seen[fp]
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
