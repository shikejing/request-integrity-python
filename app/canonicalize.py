"""Deterministic canonicalization and digesting of request content.

Canonical form (newline-joined, UTF-8):
    METHOD\nPATH\nSORTED_QUERY\nTIMESTAMP\nNONCE\nSHA256HEX(BODY)

- METHOD is upper-cased.
- QUERY is normalized by sorting key=value pairs (keys and values
  percent-decoded first, pairs with duplicate keys kept and sorted), so
  parameter order does not affect the digest.
- BODY is hashed so large bodies cost one pass and the signed string stays
  small; any single-byte change in the body changes the digest.
"""
from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl


def canonical_query(query: str) -> str:
    """Sort decoded query pairs into a stable 'k=v&...' string."""
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(
    method: str,
    path: str,
    query: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Build the canonical byte string that gets signed.

    Same content must always produce the same bytes; any field change must
    change the output.
    """
    parts = [
        method.upper(),
        path,
        canonical_query(query),
        timestamp,
        nonce,
        body_digest(body),
    ]
    return "\n".join(parts).encode("utf-8")


def content_digest(canonical: bytes) -> str:
    """Hex digest of a canonical request string."""
    return hashlib.sha256(canonical).hexdigest()
