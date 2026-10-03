"""Key registry with generation-based rotation.

A key has a generation (``key_id``), a secret, and a lifecycle status:

* ``active``   - the current key; accepted for verification and used for new
                 signatures.
* ``deprecated`` - a previous key still within its rotation window; accepted
                 for verification but no longer used for new signatures.
* ``disabled`` - a retired/revoked key; rejected on verification.

Unknown ``key_id`` values are rejected. The secret material never appears in
logs or error messages; only the non-secret ``key_id`` is referenced.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class KeyStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    DISABLED = "disabled"


@dataclass
class KeyEntry:
    """A single generation of a verification key."""

    key_id: str
    secret: bytes
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: float | None = None
    retired_at: float | None = None

    def __post_init__(self) -> None:
        if isinstance(self.secret, str):
            self.secret = self.secret.encode("utf-8")

    @property
    def is_accepted(self) -> bool:
        """Whether this key may verify signatures (active or deprecated)."""
        return self.status in (KeyStatus.ACTIVE, KeyStatus.DEPRECATED)


class KeyRegistry:
    """In-memory registry of verification keys, keyed by ``key_id``.

    Thread-safe for concurrent reads and rotation.
    """

    def __init__(self, keys: list[KeyEntry] | None = None) -> None:
        self._keys: dict[str, KeyEntry] = {}
        self._lock = __import__("threading").RLock()
        if keys:
            for entry in keys:
                self.add(entry)

    def add(self, entry: KeyEntry) -> None:
        with self._lock:
            self._keys[entry.key_id] = entry

    def get(self, key_id: str) -> KeyEntry | None:
        with self._lock:
            return self._keys.get(key_id)

    def require(self, key_id: str) -> KeyEntry:
        """Return the entry or raise :class:`KeyNotFoundError`."""
        entry = self.get(key_id)
        if entry is None:
            raise KeyNotFoundError(key_id)
        return entry

    def active(self) -> KeyEntry | None:
        """Return the current active key (the one used for new signatures)."""
        with self._lock:
            for entry in self._keys.values():
                if entry.status == KeyStatus.ACTIVE:
                    return entry
        return None

    def rotate(self, new_key_id: str, new_secret: bytes) -> KeyEntry:
        """Introduce a new active generation, deprecating the current one.

        The previous active key becomes ``deprecated`` (still accepted during
        the rotation window). Returns the newly active entry.
        """
        import time as _time

        with self._lock:
            now = _time.time()
            for entry in self._keys.values():
                if entry.status == KeyStatus.ACTIVE:
                    entry.status = KeyStatus.DEPRECATED
                    entry.retired_at = now
            new_entry = KeyEntry(
                key_id=new_key_id,
                secret=new_secret,
                status=KeyStatus.ACTIVE,
                created_at=now,
            )
            self._keys[new_key_id] = new_entry
            return new_entry

    def disable(self, key_id: str) -> None:
        """Permanently reject a key generation."""
        with self._lock:
            entry = self._keys.get(key_id)
            if entry is not None:
                entry.status = KeyStatus.DISABLED
                entry.retired_at = entry.retired_at or __import__("time").time()

    def list_key_ids(self) -> list[str]:
        with self._lock:
            return list(self._keys.keys())


class KeyNotFoundError(Exception):
    """Raised when a ``key_id`` is not present in the registry.

    This is an internal signal; the verifier maps it to a
    :class:`~integrity.errors.BadSignatureError` without leaking the reason.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(f"unknown key id: {key_id}")
        self.key_id = key_id
