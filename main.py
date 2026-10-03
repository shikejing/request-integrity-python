"""Request integrity demo service.

Wires the integrity middleware in front of a few routes that exercise the
scope model. All routes except ``/health`` require a valid signed request.
"""

from __future__ import annotations

import uvicorn
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
config = IntegrityConfig(
    max_body_bytes=1_048_576,
    timestamp_tolerance_seconds=300,
    replay_ttl_seconds=600,
    cleanup_interval_seconds=60,
)

# ---------------------------------------------------------------------------
# Keys (generation-based rotation)
# ---------------------------------------------------------------------------
keys = KeyRegistry(
    [
        KeyEntry(
            key_id="key-2024-01",
            secret=b"old-secret-material",
            status=KeyStatus.DEPRECATED,
        ),
        KeyEntry(
            key_id="key-2024-02",
            secret=b"current-secret-material",
            status=KeyStatus.ACTIVE,
        ),
    ]
)

# ---------------------------------------------------------------------------
# Callers and scopes
# ---------------------------------------------------------------------------
scopes = ScopeRegistry()
scopes.add(Caller(caller_id="caller-a", scopes={"orders:read", "orders:write"}))
scopes.add(Caller(caller_id="caller-b", scopes={"orders:read"}))
scopes.add(
    Caller(
        caller_id="caller-admin", scopes={"orders:read", "orders:write", "admin:read"}
    )
)

# ---------------------------------------------------------------------------
# Route -> required scope mapping
# ---------------------------------------------------------------------------
route_scopes: dict[tuple[str, str], str | None] = {
    ("GET", "/api/orders"): "orders:read",
    ("POST", "/api/orders"): "orders:write",
    ("GET", "/admin"): "admin:read",
    ("GET", "/"): None,
}

# ---------------------------------------------------------------------------
# Verifier and middleware
# ---------------------------------------------------------------------------
replay_store = ReplayStore(
    ttl_seconds=config.replay_ttl_seconds,
    cleanup_interval_seconds=config.cleanup_interval_seconds,
    max_records=config.max_replay_records,
    clock=config.clock,
)
verifier = IntegrityVerifier(
    config=config, keys=keys, scopes=scopes, replay_store=replay_store
)

app = FastAPI(title="Request Integrity Demo")
app.add_middleware(
    IntegrityMiddleware,
    verifier=verifier,
    route_scopes=route_scopes,
    exempt_paths=frozenset({"/health", "/healthz"}),
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


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
