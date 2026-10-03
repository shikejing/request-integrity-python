"""Configuration for the request integrity layer.

All values have safe defaults and can be overridden via environment variables
(see :func:`load_config`). Key material is never read from the environment in
plain text here; instead it is supplied to the :class:`~integrity.keys.KeyRegistry`
by the application wiring.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field

# Header names used by the integrity protocol.
HEADER_CALLER_ID = "x-caller-id"
HEADER_KEY_ID = "x-key-id"
HEADER_TIMESTAMP = "x-timestamp"
HEADER_NONCE = "x-nonce"
HEADER_SIGNATURE = "x-signature"

# Headers that are always part of the canonical signed payload.
REQUIRED_SIGNED_HEADERS: tuple[str, ...] = (
    HEADER_CALLER_ID,
    HEADER_KEY_ID,
    HEADER_TIMESTAMP,
    HEADER_NONCE,
)

# Optional headers included in the canonical payload when present.
OPTIONAL_SIGNED_HEADERS: tuple[str, ...] = ("content-type",)

# All signed headers, sorted for canonicalization.
SIGNED_HEADERS: tuple[str, ...] = tuple(
    sorted(REQUIRED_SIGNED_HEADERS + OPTIONAL_SIGNED_HEADERS)
)


@dataclass
class IntegrityConfig:
    """Runtime configuration.

    Attributes:
        max_body_bytes: Maximum accepted request body size in bytes. Bodies
            larger than this are rejected as invalid requests.
        timestamp_tolerance_seconds: Allowed clock skew between the caller and
            the server. A request is accepted only when
            ``abs(server_now - request_ts) <= tolerance``.
        replay_ttl_seconds: How long a request fingerprint is remembered for
            replay detection. Records are anchored to the request timestamp so
            that a wall-clock rollback cannot prematurely expire them.
        cleanup_interval_seconds: Minimum interval between full replay-store
            sweeps. Cleanup is throttled to avoid scanning the store on every
            request.
        max_replay_records: Hard safety cap on the number of retained replay
            records. When exceeded the oldest records are evicted.
        clock: Callable returning the current unix time in seconds. Injectable
            for deterministic tests; defaults to :func:`time.time`.
    """

    max_body_bytes: int = 1_048_576  # 1 MiB
    timestamp_tolerance_seconds: int = 300  # 5 minutes
    replay_ttl_seconds: int = 600  # 10 minutes (>= tolerance for double defense)
    cleanup_interval_seconds: int = 60
    max_replay_records: int = 1_000_000
    clock: Callable[[], float] = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.clock is None:
            import time

            self.clock = time.time

    @property
    def signed_headers(self) -> tuple[str, ...]:
        return SIGNED_HEADERS


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_config(clock: Callable[[], float] | None = None) -> IntegrityConfig:
    """Load configuration from environment variables with safe defaults.

    Environment variables:
        INTEGRITY_MAX_BODY_BYTES
        INTEGRITY_TIMESTAMP_TOLERANCE_SECONDS
        INTEGRITY_REPLAY_TTL_SECONDS
        INTEGRITY_CLEANUP_INTERVAL_SECONDS
        INTEGRITY_MAX_REPLAY_RECORDS
    """
    return IntegrityConfig(
        max_body_bytes=_env_int("INTEGRITY_MAX_BODY_BYTES", 1_048_576),
        timestamp_tolerance_seconds=_env_int(
            "INTEGRITY_TIMESTAMP_TOLERANCE_SECONDS", 300
        ),
        replay_ttl_seconds=_env_int("INTEGRITY_REPLAY_TTL_SECONDS", 600),
        cleanup_interval_seconds=_env_int("INTEGRITY_CLEANUP_INTERVAL_SECONDS", 60),
        max_replay_records=_env_int("INTEGRITY_MAX_REPLAY_RECORDS", 1_000_000),
        clock=clock,
    )
