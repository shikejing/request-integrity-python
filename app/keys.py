"""Verification keys with generation-based rotation.

Multiple keys coexist; each has a generation. During rotation the new
(ACTIVE) key signs new requests while the old (RETIRED) key still verifies
in-flight ones. REVOKED or unknown kids are rejected. Key material never
appears in repr/str/logs or error messages.
"""
from __future__ import annotations

import enum
import hmac
from dataclasses import dataclass, field

from .errors import RequestRejected, RejectionReason


class KeyStatus(enum.Enum):
    ACTIVE = "active"      # current generation, signs and verifies
    RETIRED = "retired"    # old generation, verifies only (rotation grace)
    REVOKED = "revoked"    # deactivated, must be rejected


@dataclass
class KeyRecord:
    kid: str
    generation: int
    status: KeyStatus
    _secret: bytes = field(repr=False)

    def __repr__(self) -> str:  # never leak secret
        return (
            f"KeyRecord(kid={self.kid!r}, generation={self.generation}, "
            f"status={self.status.value})"
        )

    __str__ = __repr__

    def sign(self, message: bytes) -> str:
        import hashlib

        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Constant-time comparison; malformed hex never raises."""
        try:
            expected = bytes.fromhex(self.sign(message))
            provided = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        if len(expected) != len(provided):
            return False
        return hmac.compare_digest(expected, provided)


class KeyStore:
    def __init__(self, keys: list[KeyRecord] | None = None) -> None:
        self._by_kid: dict[str, KeyRecord] = {}
        for k in keys or []:
            self._by_kid[k.kid] = k

    @classmethod
    def from_settings(
        cls,
        keys: dict[str, str],
        generations: dict[str, int],
        revoked: set[str],
    ) -> "KeyStore":
        """Build from config. Highest generation is ACTIVE, others RETIRED."""
        if not keys:
            return cls([])
        live = [kid for kid in keys if kid not in revoked]
        max_gen = max((generations.get(kid, 0) for kid in live), default=0)
        records = []
        for kid, secret in keys.items():
            gen = generations.get(kid, 0)
            if kid in revoked:
                status = KeyStatus.REVOKED
            elif gen == max_gen:
                status = KeyStatus.ACTIVE
            else:
                status = KeyStatus.RETIRED
            records.append(
                KeyRecord(kid=kid, generation=gen, status=status,
                          _secret=secret.encode("utf-8"))
            )
        return cls(records)

    def lookup(self, kid: str) -> KeyRecord:
        """Return the key for kid or raise RequestRejected."""
        rec = self._by_kid.get(kid)
        if rec is None:
            raise RequestRejected(RejectionReason.KEY_UNKNOWN,
                                  "unknown key id")
        if rec.status is KeyStatus.REVOKED:
            raise RequestRejected(RejectionReason.KEY_REVOKED,
                                  "key has been deactivated")
        return rec

    def active_key(self) -> KeyRecord:
        """The current-generation signing key."""
        for rec in self._by_kid.values():
            if rec.status is KeyStatus.ACTIVE:
                return rec
        raise RequestRejected(RejectionReason.KEY_UNKNOWN,
                              "no active signing key configured")
