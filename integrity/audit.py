"""Audit logging for integrity decisions.

Every verification decision (accepted, rejected, scope-denied) is logged with
enough context to be traceable. Key material is never logged; only the
non-secret ``key_id`` and a truncated request fingerprint are recorded.
"""

from __future__ import annotations

import logging

from .errors import Reason

# Dedicated audit logger; operators can route this to a separate sink.
audit_logger = logging.getLogger("integrity.audit")

# Also expose a standard logger for operational messages.
logger = logging.getLogger("integrity")

_FINGERPRINT_PREVIEW = 16


def _preview(fingerprint: str | None) -> str:
    if not fingerprint:
        return "-"
    return fingerprint[:_FINGERPRINT_PREVIEW]


def log_decision(
    *,
    accepted: bool,
    reason: Reason | None,
    caller_id: str | None,
    key_id: str | None,
    fingerprint: str | None,
    method: str,
    path: str,
    detail: str | None = None,
) -> None:
    """Log a single integrity decision.

    ``detail`` must never contain key material; it is a short, safe
    human-readable note.
    """
    status = "ACCEPT" if accepted else "REJECT"
    reason_value = reason.value if reason else "-"
    preview = _preview(fingerprint)
    msg = (
        f"integrity decision={status} reason={reason_value} "
        f"caller={caller_id or '-'} key={key_id or '-'} "
        f"fp={preview} method={method} path={path}"
    )
    if detail:
        msg += f" detail={detail}"

    if accepted:
        audit_logger.info(msg)
    else:
        audit_logger.warning(msg)


def log_key_event(event: str, key_id: str, detail: str | None = None) -> None:
    """Log a key lifecycle event (rotation, disable). Never logs the secret."""
    msg = f"key event={event} key_id={key_id}"
    if detail:
        msg += f" detail={detail}"
    audit_logger.info(msg)


def log_store_cleanup(removed: int, remaining: int) -> None:
    audit_logger.info(f"replay store cleanup removed={removed} remaining={remaining}")


def log_clock_rollback(previous_now: float, current_now: float) -> None:
    audit_logger.warning(
        f"clock rollback detected previous={previous_now} current={current_now}"
    )
