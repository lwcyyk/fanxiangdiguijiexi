from __future__ import annotations

from fastapi import APIRouter, HTTPException
from resolver_identity.crypto.hashes import ip_lookup_key, name_lookup_key
from resolver_identity.db.repositories import IndexerRepository


def build_lookup_router(repo: IndexerRepository) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/lookup/ip/{ip}")
    def lookup_ip(ip: str):
        row = repo.lookup(ip_lookup_key(ip))
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        return row

    @router.get("/v1/lookup/name/{name}")
    def lookup_name(name: str):
        row = repo.lookup(name_lookup_key(name))
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        return row

    return router
