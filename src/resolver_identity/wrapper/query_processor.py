from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.wrapper.dns_message import make_servfail
from resolver_identity.wrapper.request_journal import RequestJournal
from resolver_identity.verifier.resolver_verifier import ResolverVerifier

Forwarder = Callable[[bytes, str, int], Awaitable[bytes]]


@dataclass(slots=True)
class UpstreamResolver:
    ip: str
    port: int = 53
    transport: str = "udp"
    observed_resolvers: list[ResolverEndpoint] = field(default_factory=list)

    def endpoint(self) -> ResolverEndpoint:
        return ResolverEndpoint(ip=self.ip, port=self.port, transport=self.transport).normalized()

    def observed_endpoints(self) -> list[ResolverEndpoint]:
        # The first-hop upstream is always observed. Agent-provided resolvers can
        # extend this list for controlled multi-hop paths.
        endpoints = [self.endpoint()]
        endpoints.extend(endpoint.normalized() for endpoint in self.observed_resolvers)
        return endpoints


@dataclass(slots=True)
class DNSProcessResult:
    response: bytes
    request_id: str
    accepted: bool
    upstream: UpstreamResolver | None


class DNSQueryProcessor:
    """Forward DNS queries and release the first response whose resolver path verifies.

    This implements the proposal's decision rule: DNS responses are pending until
    all observed resolvers for that path verify. The first-hop upstream is always
    verified; controlled environments can attach additional Agent-observed
    resolver endpoints to the same upstream path. Observed endpoints are verified
    concurrently. Any failed resolver causes that path to be rejected and fallback
    paths are tried in order. If all paths fail, a SERVFAIL response is returned.
    """

    def __init__(self, verifier: ResolverVerifier, journal: RequestJournal | None = None):
        self.verifier = verifier
        self.journal = journal or RequestJournal()

    async def process(self, query: bytes, upstreams: list[UpstreamResolver], forwarder: Forwarder) -> DNSProcessResult:
        request_id = self.journal.create(query)
        if not upstreams:
            self.journal.add(request_id, {"event": "no_upstreams"})
            return DNSProcessResult(make_servfail(query), request_id, False, None)

        for upstream in upstreams:
            try:
                upstream_response = await forwarder(query, upstream.ip, upstream.port)
            except Exception as exc:  # pragma: no cover - exercised in integration-style smoke tests
                self.journal.add(request_id, {"upstream": upstream.endpoint().to_dict(), "event": "forward_error", "error": str(exc)})
                continue

            observed = upstream.observed_endpoints()
            verifications = await self._verify_observed(observed)
            self.journal.add(
                request_id,
                {
                    "upstream": upstream.endpoint().to_dict(),
                    "event": "path_verification",
                    "observed_resolvers": [endpoint.to_dict() for endpoint in observed],
                    "results": [result.to_dict() for result in verifications],
                },
            )
            if all(result.accepted for result in verifications):
                return DNSProcessResult(upstream_response, request_id, True, upstream)

        self.journal.add(request_id, {"event": "all_upstreams_failed"})
        return DNSProcessResult(make_servfail(query), request_id, False, None)

    async def _verify_observed(self, observed: list[ResolverEndpoint]) -> list[VerificationResult]:
        return await asyncio.gather(*(asyncio.to_thread(self.verifier.verify_endpoint, endpoint) for endpoint in observed))
