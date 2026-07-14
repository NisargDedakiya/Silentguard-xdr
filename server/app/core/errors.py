"""Global error handling.

Pre-M1, an unhandled exception in a handler surfaced a framework stack page
(Audit §16). This installs a catch-all that logs the exception with the request
correlation id and returns a stable, non-leaky JSON error envelope.

Only the *unhandled* (500) path is customized. FastAPI's built-in handlers for
``HTTPException`` and request-validation errors are left in place, so every
existing status code and response body (e.g. ``{"detail": ...}`` on a 401/404)
is unchanged — preserving backward compatibility with all current tests and
clients.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .logging import get_logger, request_id_var

log = get_logger("silentguard.errors")


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception(
        "unhandled exception",
        extra={"method": request.method, "path": request.url.path},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "internal_error",
                "detail": "An internal error occurred.",
                "request_id": request_id_var.get(),
            }
        },
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(Exception, unhandled_exception_handler)
