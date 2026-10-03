"""Caller scope (authorization) registry.

Each caller is granted a set of scopes. Each protected route requires a scope.
A request is authorized only when the caller's granted scopes include the
route's required scope. Denials are raised as
:class:`~integrity.errors.InsufficientScopeError` so they are distinguishable
from signature and replay failures.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class Caller:
    """An authenticated caller and its granted scopes."""

    caller_id: str
    scopes: set[str] = field(default_factory=set)
    display_name: str | None = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class ScopeRegistry:
    """Thread-safe registry of callers and their scopes."""

    def __init__(self) -> None:
        self._callers: dict[str, Caller] = {}
        self._lock = threading.RLock()

    def add(self, caller: Caller) -> None:
        with self._lock:
            self._callers[caller.caller_id] = caller

    def get(self, caller_id: str) -> Caller | None:
        with self._lock:
            return self._callers.get(caller_id)

    def require(self, caller_id: str) -> Caller:
        caller = self.get(caller_id)
        if caller is None:
            raise UnknownCallerError(caller_id)
        return caller

    def is_authorized(self, caller_id: str, required_scope: str | None) -> bool:
        """Return True if the caller holds the required scope.

        A ``None`` required scope means any authenticated caller is allowed.
        """
        if required_scope is None:
            return self.get(caller_id) is not None
        caller = self.get(caller_id)
        if caller is None:
            return False
        return caller.has_scope(required_scope)


class UnknownCallerError(Exception):
    """Internal signal: caller_id is not registered."""

    def __init__(self, caller_id: str) -> None:
        super().__init__(f"unknown caller: {caller_id}")
        self.caller_id = caller_id
