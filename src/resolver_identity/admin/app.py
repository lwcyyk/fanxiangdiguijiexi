from __future__ import annotations

from fastapi import FastAPI
from resolver_identity.common.config import load_settings
from resolver_identity.common.http_security import MaxRequestBodySizeMiddleware
from resolver_identity.common.health import probe_database, probe_registry
from resolver_identity.db.sqlite import connect
from resolver_identity.db.schema import init_db
from resolver_identity.db.repositories import IndexerRepository, RegistryRepository
from resolver_identity.common.registry_factory import create_registry_backend
from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.admin.routes_admin import build_admin_router


def create_app() -> FastAPI:
    settings = load_settings("admin")
    conn = connect(settings.db_path)
    init_db(conn)
    registry = create_registry_backend(settings, RegistryRepository(conn))
    publisher = AdminPublisher(
        IndexerRepository(conn),
        registry,
        settings.signature_secret,
        ed25519_private_key_b64=settings.issuer_private_key_b64 or None,
    )
    app = FastAPI(title="Resolver Identity Admin")
    app.add_middleware(MaxRequestBodySizeMiddleware, max_bytes=1024 * 1024)
    app.include_router(build_admin_router(publisher, admin_token=settings.admin_api_token or None))

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/readyz")
    def readyz():
        return {"ok": True, "database": probe_database(conn), "registry": probe_registry(registry)}

    return app

app = create_app()
