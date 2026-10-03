"""Client-side request signing helper.

This module is used by callers (and by the test suite) to produce the
integrity headers that the server verifies. It uses the exact same
canonicalization logic as the server, so a correctly signed request is always
accepted.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping

from .canonical import build_canonical, compute_signature
from .config import (
    HEADER_CALLER_ID,
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    SIGNED_HEADERS,
)


def sign_request(
    *,
    method: str,
    path: str,
    query_string: bytes | str = b"",
    body: bytes = b"",
    caller_id: str,
    key_id: str,
    secret: bytes | str,
    timestamp: float | None = None,
    nonce: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
    signed_headers: list[str] | None = None,
) -> dict[str, str]:
    """Sign a request and return the headers to send.

    The returned mapping includes the four required integrity headers plus the
    signature. ``extra_headers`` (e.g. ``content-type``) are included in the
    canonical payload when they are in the signed header set.
    """
    ts = timestamp if timestamp is not None else time.time()
    nnc = nonce if nonce is not None else uuid.uuid4().hex

    headers: dict[str, str] = {
        HEADER_CALLER_ID: caller_id,
        HEADER_KEY_ID: key_id,
        HEADER_TIMESTAMP: str(ts),
        HEADER_NONCE: nnc,
    }
    if extra_headers:
        for name, value in extra_headers.items():
            headers[name.lower()] = value

    canonical = build_canonical(
        method,
        path,
        query_string,
        headers,
        body,
        signed_headers if signed_headers is not None else SIGNED_HEADERS,
    )
    signature = compute_signature(secret, canonical)

    headers[HEADER_SIGNATURE] = signature
    return headers
