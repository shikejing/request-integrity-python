"""Rejection reasons and the rejection exception.

Rejection reasons are stable, machine-readable codes so callers and logs can
distinguish signature errors from replays, skew, unknown keys and scope
violations. Public messages never contain key material or internal details.
"""
from __future__ import annotations

import enum


class RejectionReason(enum.Enum):
    MALFORMED = "malformed_request"            # bad encoding / missing fields / oversize body
    SIGNATURE_INVALID = "signature_invalid"    # digest mismatch / tampered content
    REPLAY = "replay_detected"                 # same request seen again within window
    TIMESTAMP_EXPIRED = "timestamp_expired"    # outside tolerance window
    TIMESTAMP_SKEW = "timestamp_skew"          # too far from local clock
    KEY_UNKNOWN = "key_unknown"                # unknown kid
    KEY_REVOKED = "key_revoked"                # deactivated key
    FORBIDDEN_SCOPE = "forbidden_scope"        # caller not granted this scope


class RequestRejected(Exception):
    """Raised when a request fails integrity / anti-replay checks."""

    def __init__(self, reason: RejectionReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail  # safe, never contains secrets
        super().__init__(reason.value)
