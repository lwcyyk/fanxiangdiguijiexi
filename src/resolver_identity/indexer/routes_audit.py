from __future__ import annotations

from fastapi import APIRouter
from resolver_identity.db.repositories import AuditLogRepository


def build_audit_router(repo: AuditLogRepository) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/audit/logs")
    def list_audit_logs(limit: int = 100):
        return {"entries": repo.list(limit)}

    return router
