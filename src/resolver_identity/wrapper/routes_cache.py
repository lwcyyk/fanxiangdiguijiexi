from __future__ import annotations


from fastapi import APIRouter
from resolver_identity.chain.registry_client import SQLiteRegistryClient
from resolver_identity.db.repositories import TrustedCacheRepository
from resolver_identity.verifier.cache_manager import CacheManager


def build_cache_router(cache_repo: TrustedCacheRepository, cache: CacheManager | None = None, registry: SQLiteRegistryClient | None = None) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/cache")
    def list_cache():
        return {"entries": cache_repo.list()}

    @router.post("/v1/cache/invalidate/resolver/{resolver_id:path}")
    def invalidate_resolver(resolver_id: str, status: str = "REVOKED"):
        if cache is not None:
            cache.invalidate_resolver(resolver_id, status)
        else:
            cache_repo.mark_status_by_resolver(resolver_id, status)
        return {"resolver_id": resolver_id, "status": status}

    @router.post("/v1/cache/invalidate/root/{state_root}")
    def invalidate_root(state_root: str, status: str = "REVOKED"):
        if cache is not None:
            cache.invalidate_root(state_root, status)
        else:
            cache_repo.mark_status_by_root(state_root, status)
        return {"state_root": state_root, "status": status}

    @router.post("/v1/cache/refresh")
    def refresh_cache_state():
        if cache is None or registry is None:
            return {"checked": 0, "expired": 0, "revoked": 0, "enabled": False}
        result = cache.refresh_registry_state(registry)
        result["enabled"] = True
        return result

    return router
