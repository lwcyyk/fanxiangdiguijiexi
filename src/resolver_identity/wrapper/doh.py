from __future__ import annotations

from fastapi import APIRouter, Body, Response

from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.upstream import query_udp


def build_doh_router(coordinator: QueryCoordinator, upstreams: list[UpstreamResolver]) -> APIRouter:
    router = APIRouter()

    @router.post("/dns-query")
    async def dns_query(body: bytes = Body(..., media_type="application/dns-message")):
        result = await coordinator.coordinate(body, upstreams, query_udp)
        return Response(content=result.response, media_type="application/dns-message", headers={"X-Resolver-Identity-Request-Id": result.request_id})

    return router
