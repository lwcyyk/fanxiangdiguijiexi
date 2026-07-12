from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException
from resolver_identity.db.repositories import IndexerRepository


def build_resolvers_router(repo: IndexerRepository) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/resolvers/{resolver_id:path}/proof")
    def get_proof(resolver_id: str):
        row = repo.get_proof(resolver_id)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        return row

    @router.get("/v1/resolvers/{resolver_id:path}/status")
    def get_status(resolver_id: str):
        row = repo.get_resolver(resolver_id)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        return {"resolver_id": resolver_id, "status": row["status"]}

    @router.get("/v1/resolvers/{resolver_id:path}")
    def get_resolver(resolver_id: str):
        row = repo.get_resolver(resolver_id)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        row["object"] = json.loads(row["object_json"])
        return row

    return router
