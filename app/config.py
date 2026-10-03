"""Configuration for the integrity layer."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Settings:
    tolerance_seconds: float = 300.0      # timestamp acceptance window
    replay_window_seconds: float = 600.0  # how long nonces are remembered
    max_body_bytes: int = 1_048_576       # reject larger bodies
    keys: dict[str, str] = field(default_factory=dict)          # kid -> secret (env/config only)
    key_generations: dict[str, int] = field(default_factory=dict)
    revoked_kids: set[str] = field(default_factory=set)
    caller_scopes: dict[str, set[str]] = field(default_factory=dict)
