"""Request integrity verification and anti-replay layer.

Public API:

* :class:`~integrity.config.IntegrityConfig`
* :class:`~integrity.keys.KeyRegistry`, :class:`~integrity.keys.KeyEntry`
* :class:`~integrity.scope.ScopeRegistry`, :class:`~integrity.scope.Caller`
* :class:`~integrity.replay.ReplayStore`
* :class:`~integrity.verifier.IntegrityVerifier`
* :class:`~integrity.middleware.IntegrityMiddleware`
* :mod:`integrity.client` (signing helper)
* :class:`~integrity.errors.IntegrityError` and reason codes
"""

from .config import IntegrityConfig, load_config
from .errors import (
    BadSignatureError,
    InsufficientScopeError,
    IntegrityError,
    InternalError,
    InvalidRequestError,
    Reason,
    ReplayDetectedError,
    TimestampExpiredError,
)
from .keys import KeyEntry, KeyRegistry, KeyStatus
from .middleware import IntegrityMiddleware, get_verified_caller
from .replay import ReplayStore
from .scope import Caller, ScopeRegistry
from .verifier import IntegrityVerifier, VerificationResult

__all__ = [
    "BadSignatureError",
    "Caller",
    "InsufficientScopeError",
    "IntegrityConfig",
    "IntegrityError",
    "IntegrityMiddleware",
    "IntegrityVerifier",
    "InternalError",
    "InvalidRequestError",
    "KeyEntry",
    "KeyRegistry",
    "KeyStatus",
    "Reason",
    "ReplayDetectedError",
    "ReplayStore",
    "ScopeRegistry",
    "TimestampExpiredError",
    "VerificationResult",
    "get_verified_caller",
    "load_config",
]
