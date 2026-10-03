"""Pytest fixtures for the integrity test suite.

Provides a test app with a controllable (fake) clock so that time-dependent
behavior (timestamp windows, replay TTL, cleanup, clock rollback) can be
exercised deterministically.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI, Request

from integrity import (
    Caller,
    IntegrityConfig,
    IntegrityMiddleware,
    IntegrityVerifier,
    KeyEntry,
    KeyRegistry,
    KeyStatus,
    ReplayStore,
    ScopeRegistry,
    get_verified_caller,
)


class FakeClock:
    """A manually controlled clock for deterministic tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = float(start)

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def set(self, value: float) -> None:
        self._now = float(value)


# Fixed key material for tests.
ACTIVE_KEY_ID = "key-active"
ACTIVE_SECRET = b"active-secret"
DEPRECATED_KEY_ID = "key-deprecated"
DEPRECATED_SECRET = b"deprecated-secret"
DISABLED_KEY_ID = "key-disabled"
DISABLED_SECRET = b"disabled-secret"

CALLER_A = "caller-a"
CALLER_B = "caller-b"
CALLER_ADMIN = "caller-admin"


def build_test_app(clock: FakeClock) -> FastAPI:
    """Build a fresh test app wired with the given fake clock."""
    config = IntegrityConfig(
        max_body_bytes=1024,  # small cap to test body-too-large
        timestamp_tolerance_seconds=300,
        replay_ttl_seconds=600,
        cleanup_interval_seconds=60,
        clock=clock,
    )

    keys = KeyRegistry(
        [
            KeyEntry(
                key_id=ACTIVE_KEY_ID, secret=ACTIVE_SECRET, status=KeyStatus.ACTIVE
            ),
            KeyEntry(
                key_id=DEPRECATED_KEY_ID,
                secret=DEPRECATED_SECRET,
                status=KeyStatus.DEPRECATED,
            ),
            KeyEntry(
                key_id=DISABLED_KEY_ID,
                secret=DISABLED_SECRET,
                status=KeyStatus.DISABLED,
            ),
        ]
    )

    scopes = ScopeRegistry()
    scopes.add(Caller(caller_id=CALLER_A, scopes={"orders:read", "orders:write"}))
    scopes.add(Caller(caller_id=CALLER_B, scopes={"orders:read"}))
    scopes.add(
        Caller(
            caller_id=CALLER_ADMIN,
            scopes={"orders:read", "orders:write", "admin:read"},
        )
    )

    route_scopes: dict[tuple[str, str], str | None] = {
        ("GET", "/api/orders"): "orders:read",
        ("POST", "/api/orders"): "orders:write",
        ("GET", "/admin"): "admin:read",
        ("GET", "/"): None,
    }

    replay_store = ReplayStore(
        ttl_seconds=config.replay_ttl_seconds,
        cleanup_interval_seconds=config.cleanup_interval_seconds,
        max_records=config.max_replay_records,
        clock=clock,
    )
    verifier = IntegrityVerifier(
        config=config, keys=keys, scopes=scopes, replay_store=replay_store
    )

    app = FastAPI(title="Integrity Test App")
    app.add_middleware(
        IntegrityMiddleware,
        verifier=verifier,
        route_scopes=route_scopes,
        exempt_paths=frozenset({"/health"}),
    )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def read_root(request: Request, verified=Depends(get_verified_caller)):  # noqa: B008
        return {"Hello": "World", "caller": verified.caller_id if verified else None}

    @app.get("/api/orders")
    def list_orders(request: Request, verified=Depends(get_verified_caller)):  # noqa: B008
        return {"orders": [], "caller": verified.caller_id}

    @app.post("/api/orders")
    def create_order(request: Request, verified=Depends(get_verified_caller)):  # noqa: B008
        return {"created": True, "caller": verified.caller_id}

    @app.get("/admin")
    def admin(request: Request, verified=Depends(get_verified_caller)):  # noqa: B008
        return {"admin": True, "caller": verified.caller_id}

    # Expose internals for assertions.
    app.state.clock = clock
    app.state.verifier = verifier
    app.state.replay_store = replay_store
    app.state.keys = keys
    app.state.scopes = scopes

    return app


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def app(clock: FakeClock) -> FastAPI:
    return build_test_app(clock)
