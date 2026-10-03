"""Typed errors for the request integrity layer.

Each error carries a stable :class:`Reason` code that is safe to expose to
callers. Internal details (key material, stack traces, store internals) are
never placed on the error; they are only written to the audit log.
"""

from __future__ import annotations

from enum import Enum


class Reason(str, Enum):
    """Stable, machine-readable rejection reasons.

    The string value is what appears in HTTP responses and audit logs.
    """

    INVALID_REQUEST = "invalid_request"
    BAD_SIGNATURE = "bad_signature"
    TIMESTAMP_EXPIRED = "timestamp_expired"
    REPLAY_DETECTED = "replay_detected"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    INTERNAL_ERROR = "internal_error"


# Maps each reason to a default HTTP status code.
_STATUS_BY_REASON: dict[Reason, int] = {
    Reason.INVALID_REQUEST: 400,
    Reason.BAD_SIGNATURE: 401,
    Reason.TIMESTAMP_EXPIRED: 401,
    Reason.REPLAY_DETECTED: 409,
    Reason.INSUFFICIENT_SCOPE: 403,
    Reason.INTERNAL_ERROR: 500,
}


class IntegrityError(Exception):
    """Base class for all integrity-layer rejections.

    ``reason`` is the stable machine code; ``message`` is a generic,
    caller-safe human-readable description. Neither ever contains key
    material or internal implementation details.
    """

    def __init__(
        self,
        reason: Reason,
        message: str,
        *,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.http_status = http_status or _STATUS_BY_REASON.get(reason, 500)

    def to_response(self) -> dict:
        """Return a caller-safe JSON-serializable error body."""
        return {
            "error": {
                "reason": self.reason.value,
                "message": self.message,
            }
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(reason={self.reason.value!r}, message={self.message!r})"


class InvalidRequestError(IntegrityError):
    def __init__(self, message: str = "malformed or missing request fields") -> None:
        super().__init__(Reason.INVALID_REQUEST, message, http_status=400)


class BadSignatureError(IntegrityError):
    def __init__(self, message: str = "request signature is invalid") -> None:
        super().__init__(Reason.BAD_SIGNATURE, message, http_status=401)


class TimestampExpiredError(IntegrityError):
    def __init__(
        self, message: str = "request timestamp is outside the allowed window"
    ) -> None:
        super().__init__(Reason.TIMESTAMP_EXPIRED, message, http_status=401)


class ReplayDetectedError(IntegrityError):
    def __init__(self, message: str = "duplicate request detected") -> None:
        super().__init__(Reason.REPLAY_DETECTED, message, http_status=409)


class InsufficientScopeError(IntegrityError):
    def __init__(
        self, message: str = "caller is not authorized for this operation"
    ) -> None:
        super().__init__(Reason.INSUFFICIENT_SCOPE, message, http_status=403)


class InternalError(IntegrityError):
    def __init__(self, message: str = "internal integrity error") -> None:
        super().__init__(Reason.INTERNAL_ERROR, message, http_status=500)
