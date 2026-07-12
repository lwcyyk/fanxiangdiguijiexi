from __future__ import annotations

from fastapi import FastAPI
from resolver_identity.common.config import load_settings
from resolver_identity.common.health import probe_database
from resolver_identity.db.sqlite import connect
from resolver_identity.db.schema import init_db
from resolver_identity.db.repositories import AuditLogRepository, IndexerRepository
from resolver_identity.indexer.routes_audit import build_audit_router
from resolver_identity.indexer.routes_lookup import build_lookup_router
from resolver_identity.indexer.routes_resolvers import build_resolvers_router
from resolver_identity.indexer.routes_roots import build_roots_router


def create_app() -> FastAPI:
    settings = load_settings("indexer")
    conn = connect(settings.db_path)
    init_db(conn)
    repo = IndexerRepository(conn)
    app = FastAPI(title="Resolver Identity Indexer")
    app.include_router(build_lookup_router(repo))
    app.include_router(build_resolvers_router(repo))
    app.include_router(build_roots_router(repo))
    app.include_router(build_audit_router(AuditLogRepository(conn)))

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/readyz")
    def readyz():
        return probe_database(conn)

    return app

app = create_app()
