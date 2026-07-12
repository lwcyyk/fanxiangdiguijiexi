from __future__ import annotations

from fastapi import APIRouter, HTTPException
from resolver_identity.db.repositories import IndexerRepository


def build_roots_router(repo: IndexerRepository) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/roots/{state_root}")
    def get_root(state_root: str):
        row = repo.get_root(state_root)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        return row

    return router
