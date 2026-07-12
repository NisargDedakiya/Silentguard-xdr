"""Cross-cutting HTTP middleware: request-id correlation, access logging,
secure response headers, and a request body-size guard.

All of this is additive — it does not change any endpoint's response body or
status for well-formed requests, so it is fully backward compatible.
"""
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import settings
from .logging import get_logger, request_id_var

log = get_logger("silentguard.http")

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign/propagate a correlation id and emit one structured access log per
    request. Honors an inbound ``X-Request-ID`` so a request can be traced
    across a proxy or a calling service."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Duration is still useful on the error path; the exception handler
            # produces the response body.
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            log.exception(
                "request failed",
                extra={"method": request.method, "path": request.url.path,
                       "duration_ms": elapsed_ms},
            )
            request_id_var.reset(token)
            raise
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        response.headers[REQUEST_ID_HEADER] = rid
        log.info(
            "request",
            extra={"method": request.method, "path": request.url.path,
                   "status": response.status_code, "duration_ms": elapsed_ms},
        )
        request_id_var.reset(token)
        return response


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Add conservative security response headers. HSTS is opt-in (only useful
    over TLS) so it never breaks a plaintext local demo."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if settings.hsts_enabled:
            headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies early (defense against log-flooding via
    huge telemetry batches / event details, Audit §11.9). Uses the declared
    Content-Length; streaming bodies without one are left to the app."""

    async def dispatch(self, request: Request, call_next):
        limit = settings.max_request_bytes
        if limit > 0:
            declared = request.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > limit:
                        return JSONResponse(
                            status_code=413,
                            content={"error": {"type": "payload_too_large",
                                               "detail": f"Request body exceeds {limit} bytes"}},
                        )
                except ValueError:
                    pass
        return await call_next(request)
