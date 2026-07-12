from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx
from resolver_identity.common.agent_transport import AgentTLSConfig

from resolver_identity.agent.distributed_verifier import flatten_chain_endpoints, flatten_chain_results
from resolver_identity.agent.identity import AgentIdentity, verify_agent_identity_payload, verify_agent_identity_payload_with_public_key
from resolver_identity.agent.verification_chain import VerificationChain, verify_hop_verification_result_payload, verify_verification_chain_payload
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.wrapper.query_processor import UpstreamResolver


class ResolverChainProvider(ABC):
    """Returns only resolvers observable by local config or explicit Agent data."""

    @abstractmethod
    def observed_resolvers(self, upstream: UpstreamResolver) -> list[ResolverEndpoint]:
        raise NotImplementedError


@dataclass(slots=True)
class FirstHopResolverProvider(ResolverChainProvider):
    def observed_resolvers(self, upstream: UpstreamResolver) -> list[ResolverEndpoint]:
        return [upstream.endpoint()]


@dataclass(slots=True)
class StaticResolverChainProvider(ResolverChainProvider):
    endpoints: list[ResolverEndpoint] = field(default_factory=list)
    include_first_hop: bool = True

    @classmethod
    def from_config(cls, items: list[dict], include_first_hop: bool = True) -> "StaticResolverChainProvider":
        return cls([ResolverEndpoint.from_dict(item).normalized() for item in items], include_first_hop=include_first_hop)

    def observed_resolvers(self, upstream: UpstreamResolver) -> list[ResolverEndpoint]:
        observed = []
        if self.include_first_hop:
            observed.append(upstream.endpoint())
        observed.extend(endpoint.normalized() for endpoint in self.endpoints)
        return unique_endpoints(observed)


@dataclass(slots=True)
class ResolverChainContext:
    first_hop: ResolverEndpoint
    agent_identity: AgentIdentity
    observed_resolvers: list[ResolverEndpoint]
    config_version: str
    agent_identities: list[AgentIdentity] = field(default_factory=list)
    verification_chain: VerificationChain | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_hop": self.first_hop.to_dict(),
            "resolver_id": self.agent_identity.resolver_id,
            "config_version": self.config_version,
            "observed_resolvers": [endpoint.to_dict() for endpoint in self.observed_resolvers],
            "agent_identities": [
                {
                    "resolver_id": identity.resolver_id,
                    "endpoint": identity.endpoint.to_dict(),
                    "config_version": identity.config_version,
                    "upstreams": [endpoint.to_dict() for endpoint in identity.upstreams],
                }
                for identity in self.agent_identities
            ],
            "verification_chain": self.verification_chain.to_dict() if self.verification_chain is not None else None,
        }


class ChainDiscoveryError(RuntimeError):
    pass


@dataclass(slots=True)
class AgentResolverChainProvider(ResolverChainProvider):
    """Discover a controlled resolver chain from signed first-hop Agent evidence.

    The current distributed mode verifies only the first hop in the wrapper. R1's
    Agent returns a signed VerificationChain containing R1->R2 hop verification
    and any downstream signed Agent chains. The older identity-recursive path is
    retained as a compatibility fallback for tests and local demos.
    """

    agent_base_urls: dict[str, str]
    signature_secret: str = ""
    timeout_seconds: float = 2.0
    strict: bool = True
    max_clock_skew_seconds: int = 5
    max_depth: int = 4
    allow_hmac_fallback: bool = False
    distributed_verification: bool = True
    require_challenge: bool = False
    state_repository: Any | None = None
    tls_config: AgentTLSConfig = field(default_factory=AgentTLSConfig)
    _context_cache: dict[str, ResolverChainContext] = field(default_factory=dict)
    _invalidated_endpoints: list[ResolverEndpoint] = field(default_factory=list)

    def observed_resolvers(self, upstream: UpstreamResolver) -> list[ResolverEndpoint]:
        endpoint = upstream.endpoint()
        key = endpoint_cache_key(endpoint)
        base_url = self._agent_url_for(endpoint)
        if not base_url:
            if self.strict:
                return []
            return [endpoint]
        try:
            payload = self._fetch_identity(base_url)
            identity = verify_agent_identity_payload(
                payload,
                self.signature_secret,
                expected_endpoint=endpoint,
                max_clock_skew_seconds=self.max_clock_skew_seconds,
            )
        except Exception:
            if self.strict:
                return []
            return [endpoint]
        observed = unique_endpoints([endpoint, *identity.upstreams])
        self._record_context(key, endpoint, [identity], observed)
        return observed

    def observed_resolvers_with_verifier(self, upstream: UpstreamResolver, verifier, challenge: str | None = None) -> tuple[list[ResolverEndpoint], list[VerificationResult]]:
        if self.distributed_verification:
            return self._observe_distributed_chain(upstream, verifier, challenge=challenge)
        first = upstream.endpoint()
        observed: list[ResolverEndpoint] = []
        results: list[VerificationResult] = []
        identities: list[AgentIdentity] = []
        visiting: set[str] = set()
        self._discover(first, verifier, 0, visiting, observed, results, identities)
        observed = unique_endpoints(observed)
        if identities:
            self._record_context(endpoint_cache_key(first), first, identities, observed)
        return observed, results

    def _observe_distributed_chain(self, upstream: UpstreamResolver, verifier, challenge: str | None = None) -> tuple[list[ResolverEndpoint], list[VerificationResult]]:
        first = upstream.endpoint()
        key = endpoint_cache_key(first)
        result = verifier.verify_endpoint(first)
        if not result.accepted:
            raise ChainDiscoveryError(f"first-hop resolver identity verification failed for {key}")
        base_url = self._agent_url_for(first)
        if not base_url:
            raise ChainDiscoveryError(f"missing first-hop Agent URL for {key}")
        public_key = result.evidence.get("agent_public_key")
        algorithm = result.evidence.get("agent_key_algorithm")
        if not public_key or algorithm != "ed25519":
            raise ChainDiscoveryError("verified first-hop identity does not bind an Agent Ed25519 public key")
        payload, bound_challenge = self._fetch_chain_payload(base_url, challenge)
        if self.require_challenge and bound_challenge is None:
            raise ChainDiscoveryError("production Agent chain does not support request challenge binding")
        chain = verify_verification_chain_payload(
            payload,
            public_key,
            expected_resolver_id=result.resolver_id,
            expected_endpoint=first,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            expected_challenge=bound_challenge,
        )
        self._validate_chain_signatures(chain, first, result, expected_challenge=bound_challenge)
        observed = unique_endpoints(flatten_chain_endpoints(chain))
        if not observed:
            observed = [first]
        results = [result, *flatten_chain_results(chain)]
        if not chain.final_result:
            results.append(VerificationResult.reject("verification_chain_failed", chain.resolver_id, errors=list(chain.chain_errors)))
        self._record_context_from_chain(key, first, chain, observed)
        return observed, results

    def _validate_chain_signatures(self, chain: VerificationChain, expected_endpoint: ResolverEndpoint, first_result: VerificationResult, expected_challenge: str | None = None) -> None:
        if not chain.endpoint.matches(expected_endpoint):
            raise ChainDiscoveryError("verification chain endpoint does not match observed resolver")
        known: dict[str, tuple[str, ResolverEndpoint]] = {}
        if first_result.resolver_id and first_result.evidence.get("agent_public_key"):
            known[first_result.resolver_id] = (first_result.evidence["agent_public_key"], expected_endpoint)
        self._validate_chain_node(chain, known, set(), expected_challenge)

    def _validate_chain_node(self, chain: VerificationChain, known: dict[str, tuple[str, ResolverEndpoint]], visiting: set[str], expected_challenge: str | None = None) -> None:
        key = endpoint_cache_key(chain.endpoint)
        if key in visiting:
            raise ChainDiscoveryError(f"verification chain loop detected at {key}")
        if len(visiting) >= self.max_depth:
            raise ChainDiscoveryError("verification chain exceeded max_depth")
        visiting.add(key)
        signer = known.get(chain.resolver_id)
        if signer is None:
            raise ChainDiscoveryError(f"missing Agent public key for chain signer {chain.resolver_id}")
        public_key, signer_endpoint = signer
        verify_verification_chain_payload(
            chain.to_dict(include_signature=True),
            public_key,
            expected_resolver_id=chain.resolver_id,
            expected_endpoint=signer_endpoint,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            expected_challenge=expected_challenge,
        )
        downstream_by_resolver: dict[str, tuple[str, ResolverEndpoint]] = {}
        for hop in chain.hops:
            verify_hop_verification_result_payload(
                hop.to_dict(include_signature=True),
                public_key,
                expected_from_resolver_id=chain.resolver_id,
                expected_from_endpoint=chain.endpoint,
                max_clock_skew_seconds=self.max_clock_skew_seconds,
            )
            if endpoint_cache_key(hop.upstream_endpoint) in visiting:
                raise ChainDiscoveryError(f"verification chain loop detected at {endpoint_cache_key(hop.upstream_endpoint)}")
            if hop.accepted and hop.upstream_resolver_id and hop.evidence.get("agent_public_key"):
                downstream_by_resolver[hop.upstream_resolver_id] = (hop.evidence["agent_public_key"], hop.upstream_endpoint)
        for downstream in chain.downstream_chains:
            downstream_signer = downstream_by_resolver.get(downstream.resolver_id)
            if downstream_signer is None:
                raise ChainDiscoveryError(f"downstream chain lacks verified hop evidence for {downstream.resolver_id}")
            known[downstream.resolver_id] = downstream_signer
            self._validate_chain_node(downstream, known, visiting, expected_challenge)
        visiting.remove(key)

    def _discover(
        self,
        endpoint: ResolverEndpoint,
        verifier,
        depth: int,
        visiting: set[str],
        observed: list[ResolverEndpoint],
        results: list[VerificationResult],
        identities: list[AgentIdentity],
    ) -> None:
        endpoint = endpoint.normalized()
        key = endpoint_cache_key(endpoint)
        if key in visiting:
            raise ChainDiscoveryError(f"agent resolver chain loop detected at {key}")
        if depth >= self.max_depth:
            raise ChainDiscoveryError("agent resolver chain exceeded max_depth")
        visiting.add(key)
        observed.append(endpoint)
        result = verifier.verify_endpoint(endpoint)
        results.append(result)
        if not result.accepted:
            raise ChainDiscoveryError(f"resolver identity verification failed for {key}")

        base_url = self._agent_url_for(endpoint)
        if not base_url:
            if depth == 0 and self.strict:
                raise ChainDiscoveryError(f"missing first-hop Agent URL for {key}")
            visiting.remove(key)
            return

        payload = self._fetch_identity(base_url)
        identity = self._verify_agent_payload(payload, result, endpoint)
        if identity.resolver_id != result.resolver_id:
            raise ChainDiscoveryError("agent resolver_id does not match verified resolver identity")
        identities.append(identity)
        for upstream in identity.upstreams:
            self._discover(upstream, verifier, depth + 1, visiting, observed, results, identities)
        visiting.remove(key)

    def _verify_agent_payload(self, payload: dict[str, Any], verification: VerificationResult, endpoint: ResolverEndpoint) -> AgentIdentity:
        public_key = verification.evidence.get("agent_public_key")
        algorithm = verification.evidence.get("agent_key_algorithm")
        if public_key and algorithm == "ed25519":
            return verify_agent_identity_payload_with_public_key(
                payload,
                public_key,
                expected_endpoint=endpoint,
                max_clock_skew_seconds=self.max_clock_skew_seconds,
            )
        if self.allow_hmac_fallback and self.signature_secret:
            return verify_agent_identity_payload(
                payload,
                self.signature_secret,
                expected_endpoint=endpoint,
                max_clock_skew_seconds=self.max_clock_skew_seconds,
            )
        raise ChainDiscoveryError("verified resolver identity does not bind an Agent Ed25519 public key")

    def _record_context(self, key: str, first_hop: ResolverEndpoint, identities: list[AgentIdentity], observed: list[ResolverEndpoint]) -> None:
        config_version = ">".join(f"{identity.resolver_id}:{identity.config_version}" for identity in identities)
        context = ResolverChainContext(first_hop, identities[0], observed, config_version, list(identities))
        self._update_context(key, context)

    def _record_context_from_chain(self, key: str, first_hop: ResolverEndpoint, chain: VerificationChain, observed: list[ResolverEndpoint]) -> None:
        identity = AgentIdentity(
            resolver_id=chain.resolver_id,
            endpoint=chain.endpoint,
            upstreams=[hop.upstream_endpoint for hop in chain.hops],
            config_version=chain.config_version,
            issued_at=chain.issued_at,
            expires_at=chain.expires_at,
            issuer=chain.issuer,
            key_id=chain.key_id,
            signature=chain.signature,
        )
        config_version = chain_config_version(chain)
        context = ResolverChainContext(first_hop, identity, observed, config_version, [identity], verification_chain=chain)
        self._update_context(key, context)

    def _update_context(self, key: str, context: ResolverChainContext) -> None:
        previous = self._context_cache.get(key)
        persisted_version = self.state_repository.get(f"agent_config_high_water:{key}") if self.state_repository is not None else None
        previous_version = previous.config_version if previous else persisted_version
        if previous_version and is_config_rollback(previous_version, context.config_version):
            raise ChainDiscoveryError("agent verification chain config_version rollback detected")
        if previous and previous.config_version != context.config_version:
            self._invalidated_endpoints.extend(previous.observed_resolvers)
            self._context_cache.pop(key, None)
        self._context_cache[key] = context
        if self.state_repository is not None:
            self.state_repository.set(f"agent_config_high_water:{key}", context.config_version)

    def consume_invalidated_endpoints(self) -> list[ResolverEndpoint]:
        endpoints = unique_endpoints(self._invalidated_endpoints)
        self._invalidated_endpoints = []
        return endpoints

    def get_context(self, upstream: UpstreamResolver) -> ResolverChainContext | None:
        return self._context_cache.get(endpoint_cache_key(upstream.endpoint()))

    def _agent_url_for(self, endpoint: ResolverEndpoint) -> str | None:
        endpoint = endpoint.normalized()
        return self.agent_base_urls.get(endpoint_cache_key(endpoint)) or (self.agent_base_urls.get(endpoint.ip or "") if endpoint.ip else None)

    def _fetch_identity(self, base_url: str) -> dict[str, Any]:
        url = base_url.rstrip("/") + "/v1/identity"
        with httpx.Client(timeout=self.timeout_seconds, **self.tls_config.httpx_kwargs()) as client:
            response = client.get(url)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("agent identity response must be an object")
        return payload

    def _fetch_verification_chain(self, base_url: str, challenge: str | None = None) -> dict[str, Any]:
        url = base_url.rstrip("/") + "/v1/verification-chain"
        with httpx.Client(timeout=self.timeout_seconds, **self.tls_config.httpx_kwargs()) as client:
            response = client.post(url, json={"challenge": challenge}) if challenge else client.get(url)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("verification chain response must be an object")
        return payload

    def _fetch_chain_payload(self, base_url: str, challenge: str | None) -> tuple[dict[str, Any], str | None]:
        import inspect

        parameters = inspect.signature(self._fetch_verification_chain).parameters
        if "challenge" in parameters:
            return self._fetch_verification_chain(base_url, challenge), challenge
        return self._fetch_verification_chain(base_url), None


def chain_config_version(chain: VerificationChain) -> str:
    parts = [f"{chain.resolver_id}:{chain.config_version}"]
    for downstream in chain.downstream_chains:
        parts.append(chain_config_version(downstream))
    return ">".join(parts)


def is_config_rollback(previous: str, current: str) -> bool:
    previous_versions = parse_chain_versions(previous)
    current_versions = parse_chain_versions(current)
    for resolver_id, old_value in previous_versions.items():
        new_value = current_versions.get(resolver_id)
        if new_value is None:
            continue
        try:
            if int(new_value) < int(old_value):
                return True
        except ValueError:
            if new_value < old_value:
                return True
    return False


def parse_chain_versions(value: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for part in value.split(">"):
        if ":" not in part:
            continue
        resolver_id, config_version = part.rsplit(":", 1)
        versions[resolver_id] = config_version
    return versions

def parse_agent_base_urls(raw: str) -> dict[str, str]:
    """Parse endpoint-to-agent mappings.

    Format: endpoint_key=url pairs separated by commas. endpoint_key may be an IP
    or ip:port:transport, e.g. "192.0.2.53=http://agent:8001" or
    "192.0.2.53:53:udp=http://agent:8001".
    """
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


def endpoint_cache_key(endpoint: ResolverEndpoint) -> str:
    endpoint = endpoint.normalized()
    return f"{endpoint.ip}:{endpoint.port}:{endpoint.transport}"


def unique_endpoints(endpoints: list[ResolverEndpoint]) -> list[ResolverEndpoint]:
    unique: dict[tuple, ResolverEndpoint] = {}
    for endpoint in endpoints:
        normalized = endpoint.normalized()
        key = (normalized.ip, normalized.port, normalized.transport, normalized.server_name, normalized.uri)
        unique[key] = normalized
    return list(unique.values())
