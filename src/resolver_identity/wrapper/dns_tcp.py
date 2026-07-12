from __future__ import annotations

import asyncio

from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.upstream import query_tcp


async def handle_tcp_dns(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, coordinator: QueryCoordinator, upstreams: list[UpstreamResolver]) -> None:
    try:
        size = int.from_bytes(await reader.readexactly(2), "big")
        query = await reader.readexactly(size)
        result = await coordinator.coordinate(query, upstreams, query_tcp)
        writer.write(len(result.response).to_bytes(2, "big") + result.response)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()
