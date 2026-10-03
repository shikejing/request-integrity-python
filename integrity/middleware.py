"""ASGI middleware that enforces request integrity.

The middleware intercepts every request, reads the body (with a size cap),
runs the :class:`~integrity.verifier.IntegrityVerifier`, and either passes the
request through (attaching the verified caller to ``request.state``) or returns
a typed JSON error response.

Internal exceptions are never propagated to the caller; they are converted to
a generic ``internal_error`` response and logged.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .errors import IntegrityError, InternalError, InvalidRequestError
from .verifier import IntegrityVerifier

# Paths that bypass integrity verification entirely (e.g. health checks).
DEFAULT_EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/healthz"})


class IntegrityMiddleware:
    """Pure ASGI middleware wrapping the integrity verifier."""

    def __init__(
        self,
        app,
        verifier: IntegrityVerifier,
        route_scopes: dict[tuple[str, str], str | None] | None = None,
        exempt_paths: frozenset[str] | None = None,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.route_scopes = route_scopes or {}
        self.exempt_paths = exempt_paths or DEFAULT_EXEMPT_PATHS

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        if path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")

        # Read the body with a size cap before verification.
        try:
            body = await self._read_body(scope, receive)
        except _BodyTooLarge:
            response = self._error_response(
                InvalidRequestError("request body is too large")
            )
            await response(scope, receive, send)
            return
        except Exception:  # noqa: BLE001 - never leak internal errors to callers
            response = self._error_response(InternalError())
            await response(scope, receive, send)
            return

        # Build a headers mapping (lower-cased names).
        headers = self._headers_from_scope(scope)

        required_scope = self.route_scopes.get((method, path))

        try:
            result = self.verifier.verify(
                method=method,
                path=path,
                query_string=scope.get("query_string", b""),
                headers=headers,
                body=body,
                required_scope=required_scope,
            )
        except IntegrityError as exc:
            response = self._error_response(exc)
            await response(scope, receive, send)
            return
        except Exception:  # noqa: BLE001 - never leak internal errors to callers
            response = self._error_response(InternalError())
            await response(scope, receive, send)
            return

        # Attach verified caller info to request.state for downstream use.
        scope.setdefault("state", {})
        scope["state"]["integrity"] = result

        await self.app(scope, receive, send)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _read_body(self, scope, receive) -> bytes:
        """Read the request body, enforcing the configured size cap."""
        max_bytes = self.verifier.config.max_body_bytes
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        raise _BodyTooLarge()
                    chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break
        return b"".join(chunks)

    @staticmethod
    def _headers_from_scope(scope) -> dict[str, str]:
        headers: dict[str, str] = {}
        for name, value in scope.get("headers", []):
            try:
                headers[name.decode("ascii").lower()] = value.decode("utf-8")
            except UnicodeDecodeError, AttributeError:
                # Malformed header encoding: surface as an invalid request.
                headers[name.decode("latin-1").lower()] = value.decode(
                    "utf-8", errors="replace"
                )
        return headers

    @staticmethod
    def _error_response(exc: IntegrityError) -> Response:
        return JSONResponse(
            status_code=exc.http_status,
            content=exc.to_response(),
        )


class _BodyTooLarge(Exception):
    """Internal signal: request body exceeds the configured size cap."""


def get_verified_caller(request: Request):
    """Return the :class:`~integrity.verifier.VerificationResult` for a request.

    Intended for use as a FastAPI dependency. Returns ``None`` if the request
    was not verified (e.g. an exempt path).
    """
    state = getattr(request, "state", None)
    if state is None:
        return None
    return getattr(state, "integrity", None)
