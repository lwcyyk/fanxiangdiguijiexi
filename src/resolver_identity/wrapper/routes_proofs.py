from __future__ import annotations

from fastapi import APIRouter, HTTPException
from resolver_identity.wrapper.request_journal import RequestJournal


def build_proofs_router(journal: RequestJournal) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/proofs/{request_id}")
    def get_proof(request_id: str):
        entry = journal.get(request_id)
        if not entry:
            raise HTTPException(status_code=404, detail="request_id not found")
        return entry

    return router
