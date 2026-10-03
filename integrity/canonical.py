"""Canonical request representation and HMAC signing.

The canonical form is a deterministic, order-independent serialization of the
request's key content. Both the client (signer) and the server (verifier) must
build the exact same string for the same request. Any change to a covered
field changes the canonical string and therefore the signature.

Canonical layout (newline separated)::

    METHOD
    PATH
    SORTED_QUERY
    HEADER_NAME:HEADER_VALUE
    ...
    BODY_SHA256_HEX

* ``METHOD`` is the upper-case HTTP method.
* ``PATH`` is the request path (no query string), taken as received.
* ``SORTED_QUERY`` is the query string with parameters sorted by key then value.
* Signed headers are listed alphabetically by lower-cased name, one per line,
  as ``name:value``. Values are stripped of leading/trailing whitespace.
* ``BODY_SHA256_HEX`` is the hex digest of SHA-256 over the raw body bytes.

The signature is ``HMAC-SHA256(key_secret, canonical_string)`` hex-encoded.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping
from urllib.parse import parse_qsl, urlencode

from .config import SIGNED_HEADERS


def hash_body(body: bytes) -> str:
    """Return the SHA-256 hex digest of the raw body bytes."""
    return hashlib.sha256(body).hexdigest()


def canonical_query_string(query_string: bytes | str) -> str:
    """Serialize a query string deterministically (sorted by key then value)."""
    if isinstance(query_string, bytes):
        query_string = query_string.decode("utf-8", errors="replace")
    pairs = parse_qsl(query_string, keep_blank_values=True, strict_parsing=False)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return urlencode(pairs)


def _normalize_header_value(value: str) -> str:
    """Trim a header value without altering its internal content."""
    return value.strip()


def build_canonical(
    method: str,
    path: str,
    query_string: bytes | str,
    headers: Mapping[str, str],
    body: bytes,
    signed_headers: Iterable[str] | None = None,
) -> str:
    """Build the canonical string that is signed.

    Args:
        method: HTTP method (case-insensitive; normalized to upper).
        path: Request path without query string.
        query_string: Raw query string (bytes or str).
        headers: Mapping of lower-cased header name to value.
        body: Raw request body bytes.
        signed_headers: Override the default signed header set.

    Returns:
        The deterministic canonical string.
    """
    if signed_headers is None:
        signed_headers = SIGNED_HEADERS
    signed = sorted({h.lower() for h in signed_headers})

    method_part = method.upper()
    path_part = path
    query_part = canonical_query_string(query_string)
    body_part = hash_body(body)

    header_lines: list[str] = []
    for name in signed:
        if name in headers:
            header_lines.append(f"{name}:{_normalize_header_value(headers[name])}")

    parts = [method_part, path_part, query_part]
    parts.extend(header_lines)
    parts.append(body_part)
    return "\n".join(parts)


def compute_signature(secret: bytes | str, canonical: str) -> str:
    """Compute the HMAC-SHA256 signature (hex) of the canonical string."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(
    secret: bytes | str, canonical: str, provided_signature: str
) -> bool:
    """Constant-time comparison of a provided signature against the expected."""
    if not provided_signature:
        return False
    expected = compute_signature(secret, canonical)
    try:
        return hmac.compare_digest(expected, provided_signature.strip().lower())
    except TypeError, ValueError:
        return False
