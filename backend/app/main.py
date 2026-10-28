"""FastAPI application entrypoint (also the Vercel Python entrypoint: app/main.py:app)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings
from app.routers import admin, alerts, auth, custom_playbooks, dashboard, detections, events, health, incidents, iocs, response

log = logging.getLogger("sentinelforge")

API_PREFIX = "/api/v1"


class BodySizeLimitMiddleware:
    """Reject request bodies over the configured size, even without Content-Length."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        settings = get_settings()
        limit = settings.max_ingest_body_bytes if scope["path"].startswith(f"{API_PREFIX}/ingest/") else settings.max_body_bytes
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await _reject(send, 413, "Request body too large")
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _reject(send, 413, "Request body too large")


class _BodyTooLarge(Exception):
    pass


async def _reject(send: Send, status: int, detail: str) -> None:
    body = JSONResponse({"detail": detail}, status_code=status).body
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SentinelForge IR API",
        version=settings.app_version,
        description="Incident response and security engineering platform. All demo data is synthetic.",
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        request_id = request.headers.get("x-request-id", "")
        if not request_id or len(request_id) > 64 or not request_id.replace("-", "").isalnum():
            request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = request_id
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.url.path.startswith(f"{API_PREFIX}/docs"):
            resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if request.url.path.startswith(API_PREFIX):
            resp.headers["Cache-Control"] = "no-store"
        if settings.is_production:
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return resp

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
        )
    app.add_middleware(BodySizeLimitMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Strip echoed input values so secrets (e.g. passwords) never appear in responses or logs.
        errors = [{k: v for k, v in err.items() if k not in ("input", "ctx", "url")} for err in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        log.exception("unhandled error request_id=%s path=%s", rid, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": rid})

    for r in (health, auth, dashboard, incidents, alerts, events, detections, iocs, response, custom_playbooks, admin):
        app.include_router(r.router, prefix=API_PREFIX)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {"service": "SentinelForge IR API", "docs": f"{API_PREFIX}/docs", "health": f"{API_PREFIX}/health"}

    return app


app = create_app()
