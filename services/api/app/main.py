from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from app.api import (
    account,
    admin,
    api_keys,
    assess,
    auth,
    breach,
    channels,
    devices,
    extension,
    groups,
    intelligence,
    metrics,
    push,
    reports,
    scans,
    sharing,
    system,
    trends,
    user,
    vault,
    vpn,
    webhooks,
)
from app.core.config import get_settings
from app.core.errors import register_error_handlers

API_PREFIX = "/api/v1"

# The API only ever returns JSON, so it can use the most restrictive policy there is.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}
_DOCS_PATHS = (f"{API_PREFIX}/docs", f"{API_PREFIX}/openapi.json")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SENTINEL API",
        version="0.1.0",
        description="Scanning, account and system endpoints for the SENTINEL platform.",
        docs_url=f"{API_PREFIX}/docs",
        openapi_url=f"{API_PREFIX}/openapi.json",
        redoc_url=None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
        )

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            # The interactive docs page loads its own scripts and needs a looser policy.
            if header == "Content-Security-Policy" and request.url.path in _DOCS_PATHS:
                continue
            response.headers.setdefault(header, value)
        return response

    register_error_handlers(app)
    for router in (
        auth.router,
        account.router,
        scans.router,
        user.router,
        extension.router,
        intelligence.router,
        reports.router,
        admin.router,
        api_keys.router,
        metrics.router,
        system.router,
        sharing.router,
        groups.router,
        webhooks.router,
        channels.router,
        breach.router,
        push.router,
        trends.router,
        devices.router,
        vault.router,
        vpn.router,
        assess.router,
    ):
        app.include_router(router, prefix=API_PREFIX)
    return app


app = create_app()
