from __future__ import annotations

import asyncio

from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.upstream import query_udp
from resolver_identity.wrapper.dns_message import make_servfail


class UDPDNSServer(asyncio.DatagramProtocol):
    def __init__(self, coordinator: QueryCoordinator, upstreams: list[UpstreamResolver], max_inflight: int = 512):
        self.coordinator = coordinator
        self.upstreams = upstreams
        self.transport = None
        self.max_inflight = max_inflight
        self.tasks: set[asyncio.Task] = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(self.tasks) >= self.max_inflight:
            self.transport.sendto(make_servfail(data), addr)
            return
        task = asyncio.create_task(self._handle(data, addr))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _handle(self, data: bytes, addr):
        result = await self.coordinator.coordinate(data, self.upstreams, query_udp)
        self.transport.sendto(result.response, addr)
