"""FastAPI integration: dependency that enforces integrity checks.

Rejection reasons are surfaced to the caller as stable machine-readable
codes; internal exception details and key material are never exposed.
"""
from __future__ import annotations

import os

from fastapi import HTTPException, Request

from .config import Settings
from .errors import RequestRejected, RejectionReason
from .keys import KeyStore
from .replay import ReplayStore
from .verifier import SignedRequest, Verifier

H_CALLER = "x-caller-id"
H_SCOPE = "x-scope"
H_KID = "x-key-id"
H_TS = "x-timestamp"
H_NONCE = "x-nonce"
H_SIG = "x-signature"

_STATUS_BY_REASON = {
    RejectionReason.MALFORMED: 400,
    RejectionReason.SIGNATURE_INVALID: 401,
    RejectionReason.TIMESTAMP_EXPIRED: 401,
    RejectionReason.TIMESTAMP_SKEW: 401,
    RejectionReason.KEY_UNKNOWN: 401,
    RejectionReason.KEY_REVOKED: 401,
    RejectionReason.FORBIDDEN_SCOPE: 403,
    RejectionReason.REPLAY: 409,
}


def settings_from_env() -> Settings:
    """Load settings from environment (INTEGRITY_* variables)."""
    keys: dict[str, str] = {}
    generations: dict[str, int] = {}
    for kid in (os.environ.get("INTEGRITY_KEY_IDS") or "").split(","):
        kid = kid.strip()
        if not kid:
            continue
        secret = os.environ.get(f"INTEGRITY_KEY_{kid.upper()}")
        if secret:
            keys[kid] = secret
            generations[kid] = int(
                os.environ.get(f"INTEGRITY_KEYGEN_{kid.upper()}", "0"))
    revoked = {k.strip() for k in
               (os.environ.get("INTEGRITY_REVOKED_KIDS") or "").split(",")
               if k.strip()}
    scopes: dict[str, set[str]] = {}
    for pair in (os.environ.get("INTEGRITY_CALLER_SCOPES") or "").split(","):
        if ":" in pair:
            caller, scope_list = pair.split(":", 1)
            scopes[caller.strip()] = {s.strip() for s in scope_list.split("|")
                                      if s.strip()}
    return Settings(
        tolerance_seconds=float(os.environ.get("INTEGRITY_TOLERANCE_SECONDS", "300")),
        replay_window_seconds=float(os.environ.get("INTEGRITY_REPLAY_WINDOW_SECONDS", "600")),
        max_body_bytes=int(os.environ.get("INTEGRITY_MAX_BODY_BYTES", "1048576")),
        keys=keys,
        key_generations=generations,
        revoked_kids=revoked,
        caller_scopes=scopes,
    )


def build_verifier(settings: Settings | None = None) -> Verifier:
    """Construct a Verifier from Settings (defaults: environment)."""
    s = settings or settings_from_env()
    keystore = KeyStore.from_settings(s.keys, s.key_generations, s.revoked_kids)
    replay = ReplayStore(s.replay_window_seconds)
    return Verifier(
        keystore=keystore,
        replay_store=replay,
        caller_scopes=s.caller_scopes,
        tolerance_seconds=s.tolerance_seconds,
        max_body_bytes=s.max_body_bytes,
    )


async def require_integrity(request: Request) -> None:
    """FastAPI dependency; rejects unsigned/tampered/replayed requests."""
    verifier: Verifier = request.app.state.verifier
    body = await request.body()
    if len(body) > verifier._max_body:
        raise HTTPException(status_code=400,
                            detail=RejectionReason.MALFORMED.value)
    headers = request.headers
    req = SignedRequest(
        caller_id=headers.get(H_CALLER, ""),
        scope=headers.get(H_SCOPE, ""),
        kid=headers.get(H_KID, ""),
        timestamp=headers.get(H_TS, ""),
        nonce=headers.get(H_NONCE, ""),
        signature=headers.get(H_SIG, ""),
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        body=body,
    )
    try:
        verifier.verify(req)
    except RequestRejected as e:
        # Only the stable reason code is exposed; details stay in logs.
        raise HTTPException(
            status_code=_STATUS_BY_REASON.get(e.reason, 400),
            detail=e.reason.value,
        ) from None
