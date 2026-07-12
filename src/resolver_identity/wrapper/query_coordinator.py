from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from dataclasses import dataclass
from dataclasses import field

from resolver_identity.db.repositories import AuditLogRepository
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.verifier.resolver_verifier import ResolverVerifier
from resolver_identity.wrapper.dns_message import make_servfail
from resolver_identity.wrapper.dns_parse import parse_question
from resolver_identity.wrapper.query_processor import DNSProcessResult, Forwarder, UpstreamResolver
from resolver_identity.wrapper.request_journal import RequestJournal
from resolver_identity.wrapper.metrics import RuntimeMetrics
from resolver_identity.wrapper.resolver_chain import FirstHopResolverProvider, ResolverChainProvider


@dataclass(slots=True)
class QueryCoordinator:
    verifier: ResolverVerifier
    chain_provider: ResolverChainProvider | None = None
    audit: AuditLogRepository | None = None
    journal: RequestJournal | None = None
    strict_observation: bool = True
    metrics: RuntimeMetrics = field(default_factory=RuntimeMetrics)
    verification_deadline_seconds: float = 1.5

    def __post_init__(self) -> None:
        if self.chain_provider is None:
            self.chain_provider = FirstHopResolverProvider()
        if self.journal is None:
            self.journal = RequestJournal()

    async def coordinate(self, query: bytes, upstreams: list[UpstreamResolver], forwarder: Forwarder) -> DNSProcessResult:
        request_id = self.journal.create(query)
        challenge = secrets.token_urlsafe(32)
        qname, qtype = parse_question(query)
        start = time.perf_counter()
        final_reason = None
        last_observed: list[ResolverEndpoint] = []
        last_results: list[VerificationResult] = []

        if not upstreams:
            final_reason = "no_upstreams"
            response = make_servfail(query)
            self._audit(request_id, qname, qtype, [], [], "SERVFAIL", final_reason, start)
            return DNSProcessResult(response, request_id, False, None)

        for upstream in upstreams:
            observation_task = asyncio.create_task(
                asyncio.wait_for(
                    asyncio.to_thread(self._observe_resolvers, upstream, challenge),
                    timeout=self.verification_deadline_seconds,
                )
            )
            forward_task = asyncio.create_task(forwarder(query, upstream.ip, upstream.port))
            observation_outcome, forward_outcome = await asyncio.gather(
                observation_task,
                forward_task,
                return_exceptions=True,
            )
            if isinstance(observation_outcome, BaseException):
                final_reason = "chain_discovery_failed"
                self.journal.add(request_id, {"event": "chain_discovery_failed", "upstream": upstream.endpoint().to_dict(), "error": str(observation_outcome)})
                continue
            observed, preverified = observation_outcome
            invalidated_endpoints = self._consume_chain_invalidations()
            for invalidated in invalidated_endpoints:
                self.verifier.cache.invalidate_endpoint(invalidated, "EXPIRED")
            if invalidated_endpoints and preverified is not None:
                if getattr(self.chain_provider, "distributed_verification", False):
                    first_result = await asyncio.to_thread(self.verifier.verify_endpoint, upstream.endpoint())
                    preverified = [first_result, *preverified[1:]]
                else:
                    preverified = await self._verify_all(observed)
            if not observed and self.strict_observation:
                final_reason = "no_observable_resolvers"
                self.journal.add(request_id, {"event": "strict_observation_reject", "upstream": upstream.endpoint().to_dict()})
                continue

            if isinstance(forward_outcome, BaseException):
                final_reason = "dns_forward_error"
                self.journal.add(request_id, {"event": "forward_error", "upstream": upstream.endpoint().to_dict(), "error": str(forward_outcome)})
                continue
            upstream_response = forward_outcome

            verifications = preverified if preverified is not None else await self._verify_all(observed)
            last_observed = observed
            last_results = verifications
            self.journal.add(
                request_id,
                {
                    "event": "identity_gate",
                    "qname": qname,
                    "qtype": qtype,
                    "upstream": upstream.endpoint().to_dict(),
                    "observed_resolvers": [endpoint.to_dict() for endpoint in observed],
                    "results": [result.to_dict() for result in verifications],
                },
            )
            if self._agent_identity_mismatch(upstream, verifications):
                final_reason = "agent_resolver_id_mismatch"
                self.journal.add(request_id, {"event": "agent_identity_mismatch", "upstream": upstream.endpoint().to_dict()})
                continue
            if all(result.accepted for result in verifications) and all(self.verifier.cache.result_is_current(result) for result in verifications):
                self._audit(request_id, qname, qtype, observed, verifications, "ALLOW", None, start)
                return DNSProcessResult(upstream_response, request_id, True, upstream)
            if all(result.accepted for result in verifications):
                final_reason = "verification_invalidated_before_release"
                continue
            final_reason = first_failure(verifications) or "identity_verification_failed"

        response = make_servfail(query)
        self._audit(request_id, qname, qtype, last_observed, last_results, "SERVFAIL", final_reason or "all_paths_failed", start)
        return DNSProcessResult(response, request_id, False, None)

    def _observe_resolvers(self, upstream: UpstreamResolver, challenge: str | None = None) -> tuple[list[ResolverEndpoint], list[VerificationResult] | None]:
        observer = getattr(self.chain_provider, "observed_resolvers_with_verifier", None)
        if observer is not None:
            if "challenge" in inspect.signature(observer).parameters:
                return observer(upstream, self.verifier, challenge=challenge)
            return observer(upstream, self.verifier)
        return self.chain_provider.observed_resolvers(upstream), None

    async def _verify_all(self, observed: list[ResolverEndpoint]) -> list[VerificationResult]:
        results = await asyncio.gather(*(asyncio.to_thread(self.verifier.verify_endpoint, endpoint) for endpoint in observed))
        for endpoint, result in zip(observed, results):
            if result.accepted and result.status == "REFRESHING":
                asyncio.create_task(asyncio.to_thread(self.verifier.refresh_endpoint, endpoint))
        return results

    def _consume_chain_invalidations(self) -> list[ResolverEndpoint]:
        consumer = getattr(self.chain_provider, "consume_invalidated_endpoints", None)
        if consumer is None:
            return []
        return consumer()

    def _agent_identity_mismatch(self, upstream: UpstreamResolver, results: list[VerificationResult]) -> bool:
        context_getter = getattr(self.chain_provider, "get_context", None)
        if context_getter is None:
            return False
        context = context_getter(upstream)
        if context is None or not results:
            return False
        first_result = results[0]
        return first_result.accepted and first_result.resolver_id != context.agent_identity.resolver_id

    def _audit(
        self,
        request_id: str,
        qname: str,
        qtype: str,
        observed: list[ResolverEndpoint],
        results: list[VerificationResult],
        decision: str,
        failure_reason: str | None,
        start: float,
    ) -> None:
        total_latency_ms = (time.perf_counter() - start) * 1000
        payload = {
            "request_id": request_id,
            "qname": qname,
            "qtype": qtype,
            "resolvers": [endpoint.to_dict() for endpoint in observed],
            "cache": [result.evidence.get("cache", "miss") for result in results],
            "verification_results": [result.to_dict() for result in results],
            "object_hashes": [result.evidence.get("object_hash") for result in results if result.evidence.get("object_hash")],
            "state_roots": [result.evidence.get("state_root") for result in results if result.evidence.get("state_root")],
            "decision": decision,
            "failure_reason": failure_reason,
            "total_latency_ms": total_latency_ms,
        }
        self.journal.add(request_id, {"event": "final_decision", **payload})
        if self.audit is not None:
            self.audit.record("QueryDecision", payload)
        self.metrics.record_decision(decision, total_latency_ms, results)


def first_failure(results: list[VerificationResult]) -> str | None:
    for result in results:
        if not result.accepted:
            return result.reasons[0] if result.reasons else "identity_verification_failed"
    return None
