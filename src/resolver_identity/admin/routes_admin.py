from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException
from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.crypto.hashes import resolver_id_key


def build_admin_router(publisher: AdminPublisher, admin_token: str | None = None) -> APIRouter:
    def authorize(x_admin_token: str | None = Header(default=None)) -> None:
        if admin_token is None:
            return
        if x_admin_token is None or not hmac.compare_digest(x_admin_token, admin_token):
            raise HTTPException(status_code=401, detail="invalid admin token")

    router = APIRouter(dependencies=[Depends(authorize)])

    @router.post("/v1/admin/resolvers")
    def create_resolver(payload: dict):
        try:
            obj = build_resolver_object(**payload)
            return publisher.publish(obj)
        except (KeyError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="invalid resolver object payload") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/v1/admin/resolvers/{resolver_id:path}/revoke")
    def revoke_resolver(resolver_id: str):
        publisher.registry.revoke_resolver(resolver_id_key(resolver_id))
        return {"resolver_id": resolver_id, "status": "REVOKED"}

    @router.post("/v1/admin/roots/publish")
    def publish_root(payload: dict):
        publisher.registry.publish_root(payload["state_root"], payload.get("status", "ACTIVE"))
        publisher.indexer.publish_root(payload["state_root"], payload.get("status", "ACTIVE"))
        return {"state_root": payload["state_root"], "status": payload.get("status", "ACTIVE")}

    @router.post("/v1/admin/operators")
    def operators(payload: dict):
        raise HTTPException(status_code=501, detail="operator management is not implemented")

    @router.post("/v1/admin/resolvers/{resolver_id:path}/endpoints")
    def endpoints(resolver_id: str, payload: dict):
        raise HTTPException(status_code=501, detail="publish a new resolver object version to change endpoints")

    return router
