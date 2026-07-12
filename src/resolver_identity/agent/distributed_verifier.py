from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from resolver_identity.common.agent_transport import AgentTLSConfig

from resolver_identity.agent.verification_chain import (
    HopVerificationResult,
    VerificationChain,
    sign_hop_verification_result,
    sign_verification_chain,
    verify_verification_chain_payload,
)
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.verifier.resolver_verifier import ResolverVerifier


class DistributedVerificationError(RuntimeError):
    pass


@dataclass(slots=True)
class DistributedAgentVerifier:
    resolver_id: str
    endpoint: ResolverEndpoint
    upstreams: list[ResolverEndpoint]
    config_version: str
    private_key_b64: str
    verifier: ResolverVerifier
    agent_base_urls: dict[str, str] = field(default_factory=dict)
    terminal_upstreams: list[ResolverEndpoint] = field(default_factory=list)
    timeout_seconds: float = 2.0
    max_age_seconds: int = 30
    max_depth: int = 4
    max_clock_skew_seconds: int = 5
    issuer: str = "resolver-agent"
    key_id: str = "agent-key-01"
    tls_config: AgentTLSConfig = field(default_factory=AgentTLSConfig)

    @classmethod
    def from_raw_agent_urls(cls, *args, raw_agent_base_urls: str = "", **kwargs) -> "DistributedAgentVerifier":
        return cls(*args, agent_base_urls=parse_agent_base_urls(raw_agent_base_urls) if raw_agent_base_urls else {}, **kwargs)

    def build_chain_payload(self, challenge: str | None = None) -> dict[str, Any]:
        chain = self._build_chain(depth=0, visiting={endpoint_cache_key(self.endpoint)}, challenge=challenge)
        return sign_verification_chain(chain, self.private_key_b64)

    def _build_chain(self, depth: int, visiting: set[str], challenge: str | None) -> VerificationChain:
        if depth >= self.max_depth:
            chain = self._empty_chain(["agent verification chain exceeded max_depth"], challenge)
            return chain

        hops: list[HopVerificationResult] = []
        downstream_chains: list[VerificationChain] = []
        terminal_upstreams: list[ResolverEndpoint] = []
        chain_errors: list[str] = []

        for upstream in self.upstreams:
            upstream = upstream.normalized()
            if self._is_terminal_upstream(upstream):
                terminal_upstreams.append(upstream)
                continue
            result = self.verifier.verify_endpoint(upstream)
            hop = HopVerificationResult.from_verification_result(
                self.resolver_id,
                self.endpoint,
                upstream,
                result,
                max_age_seconds=self.max_age_seconds,
                issuer=self.issuer,
                key_id=self.key_id,
            )
            sign_hop_verification_result(hop, self.private_key_b64)
            hops.append(hop)
            if not result.accepted:
                chain_errors.append(f"upstream verification failed for {endpoint_cache_key(upstream)}")
                continue

            downstream_url = self._agent_url_for(upstream)
            if not downstream_url:
                chain_errors.append(f"verified recursive upstream has no configured adjacent Agent: {endpoint_cache_key(upstream)}")
                continue

            upstream_key = endpoint_cache_key(upstream)
            if upstream_key in visiting:
                chain_errors.append(f"agent verification chain loop detected at {upstream_key}")
                continue
            public_key = result.evidence.get("agent_public_key")
            algorithm = result.evidence.get("agent_key_algorithm")
            if not public_key or algorithm != "ed25519":
                chain_errors.append(f"verified upstream does not bind Agent Ed25519 public key: {upstream_key}")
                continue

            try:
                payload = self._fetch_verification_chain(downstream_url, challenge)
                downstream_chain = verify_verification_chain_payload(
                    payload,
                    public_key,
                    expected_resolver_id=result.resolver_id,
                    expected_endpoint=upstream,
                    max_clock_skew_seconds=self.max_clock_skew_seconds,
                    expected_challenge=challenge,
                )
            except Exception as exc:
                chain_errors.append(f"downstream chain verification failed for {upstream_key}: {exc}")
                continue
            if not downstream_chain.final_result:
                chain_errors.append(f"downstream chain rejected for {upstream_key}")
            downstream_chains.append(downstream_chain)

        final_result = all(hop.accepted for hop in hops) and all(chain.final_result for chain in downstream_chains) and not chain_errors
        return VerificationChain(
            resolver_id=self.resolver_id,
            endpoint=self.endpoint.normalized(),
            config_version=self.config_version,
            challenge=challenge,
            hops=hops,
            downstream_chains=downstream_chains,
            terminal_upstreams=terminal_upstreams,
            chain_errors=chain_errors,
            final_result=final_result,
            issuer=self.issuer,
            key_id=self.key_id,
        )

    def _empty_chain(self, errors: list[str], challenge: str | None = None) -> VerificationChain:
        return VerificationChain(
            resolver_id=self.resolver_id,
            endpoint=self.endpoint.normalized(),
            config_version=self.config_version,
            challenge=challenge,
            chain_errors=errors,
            final_result=False,
            issuer=self.issuer,
            key_id=self.key_id,
        )

    def _agent_url_for(self, endpoint: ResolverEndpoint) -> str | None:
        endpoint = endpoint.normalized()
        return self.agent_base_urls.get(endpoint_cache_key(endpoint)) or (self.agent_base_urls.get(endpoint.ip or "") if endpoint.ip else None)

    def _is_terminal_upstream(self, endpoint: ResolverEndpoint) -> bool:
        return any(candidate.matches(endpoint) for candidate in self.terminal_upstreams)

    def _fetch_verification_chain(self, base_url: str, challenge: str | None = None) -> dict[str, Any]:
        url = base_url.rstrip("/") + "/v1/verification-chain"
        with httpx.Client(timeout=self.timeout_seconds, **self.tls_config.httpx_kwargs()) as client:
            response = client.post(url, json={"challenge": challenge}) if challenge else client.get(url)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("verification chain response must be an object")
        return payload


def flatten_chain_endpoints(chain: VerificationChain) -> list[ResolverEndpoint]:
    endpoints: list[ResolverEndpoint] = [chain.endpoint]
    for hop in chain.hops:
        endpoints.append(hop.upstream_endpoint)
    for downstream in chain.downstream_chains:
        endpoints.extend(flatten_chain_endpoints(downstream))
    return _unique_endpoints(endpoints)


def flatten_chain_results(chain: VerificationChain) -> list[VerificationResult]:
    results: list[VerificationResult] = []
    for hop in chain.hops:
        results.append(hop.to_verification_result())
    for downstream in chain.downstream_chains:
        results.extend(flatten_chain_results(downstream))
    if chain.chain_errors:
        results.append(VerificationResult.reject("verification_chain_failed", chain.resolver_id, errors=list(chain.chain_errors)))
    return results



def _unique_endpoints(endpoints: list[ResolverEndpoint]) -> list[ResolverEndpoint]:
    unique: dict[tuple, ResolverEndpoint] = {}
    for endpoint in endpoints:
        normalized = endpoint.normalized()
        unique[(normalized.ip, normalized.port, normalized.transport, normalized.server_name, normalized.uri)] = normalized
    return list(unique.values())


def endpoint_cache_key(endpoint: ResolverEndpoint) -> str:
    endpoint = endpoint.normalized()
    return f"{endpoint.ip}:{endpoint.port}:{endpoint.transport}"


def parse_agent_base_urls(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        endpoint_spec, url = item.split("=", 1)
        parts = endpoint_spec.split(":")
        if len(parts) == 1:
            out[parts[0]] = url
        elif len(parts) == 2:
            endpoint = ResolverEndpoint(ip=parts[0], port=int(parts[1]), transport="udp").normalized()
            out[endpoint_cache_key(endpoint)] = url
        else:
            endpoint = ResolverEndpoint(ip=parts[0], port=int(parts[1]), transport=parts[2]).normalized()
            out[endpoint_cache_key(endpoint)] = url
    return out
