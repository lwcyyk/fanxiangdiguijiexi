from __future__ import annotations

from fastapi import APIRouter
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.verifier.resolver_verifier import ResolverVerifier


def build_verify_router(verifier: ResolverVerifier) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/verify/resolver")
    def verify_resolver(payload: dict):
        result = verifier.verify_endpoint(ResolverEndpoint.from_dict(payload["endpoint"]))
        return result.to_dict()

    @router.post("/v1/verify/query")
    def verify_query(payload: dict):
        endpoints = [ResolverEndpoint.from_dict(e) for e in payload.get("observed_resolvers", [])]
        if not endpoints:
            return {"accepted": False, "reason": "no_observed_resolvers", "results": []}
        results = [verifier.verify_endpoint(e).to_dict() for e in endpoints]
        return {"accepted": all(r["accepted"] for r in results), "results": results}

    return router
