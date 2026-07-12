import copy
import time

import pytest

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.agent.identity import build_agent_identity, build_agent_identity_ed25519, verify_agent_identity_payload
from resolver_identity.agent.verification_chain import HopVerificationResult, VerificationChain, sign_hop_verification_result, sign_verification_chain
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.crypto.signatures import generate_ed25519_keypair
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.resolver_chain import AgentResolverChainProvider, parse_agent_base_urls

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
ORIGINAL_RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"


R1_AGENT_PRIVATE, R1_AGENT_PUBLIC = generate_ed25519_keypair()
R2_AGENT_PRIVATE, R2_AGENT_PUBLIC = generate_ed25519_keypair()
R3_AGENT_PRIVATE, R3_AGENT_PUBLIC = generate_ed25519_keypair()


async def forward_ok(query, host, port):
    return ORIGINAL_RESPONSE


def publish(stack, ip, resolver_id, agent_public_key_b64=None):
    obj = build_resolver_object(
        resolver_id,
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
        agent_public_key_b64=agent_public_key_b64,
    )
    stack.publisher.publish(obj)
    return obj


def signed_identity(resolver_id="operator-a/r1", endpoint_ip="192.0.2.53", upstream_ip="192.0.2.54", config_version="1", secret="agent-secret"):
    return build_agent_identity(
        resolver_id=resolver_id,
        endpoint=ResolverEndpoint(ip=endpoint_ip, port=53, transport="udp"),
        upstreams=[ResolverEndpoint(ip=upstream_ip, port=53, transport="udp")],
        config_version=config_version,
        signature_secret=secret,
        max_age_seconds=30,
    )


def test_agent_identity_signature_binds_endpoint_upstreams_and_config_version():
    payload = signed_identity()
    identity = verify_agent_identity_payload(payload, "agent-secret", expected_endpoint=ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert identity.resolver_id == "operator-a/r1"
    assert identity.upstreams[0].ip == "192.0.2.54"
    assert identity.config_version == "1"

    tampered = dict(payload)
    tampered["upstreams"] = [ResolverEndpoint(ip="192.0.2.99", port=53, transport="udp").to_dict()]
    try:
        verify_agent_identity_payload(tampered, "agent-secret", expected_endpoint=ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    except ValueError as exc:
        assert "signature" in str(exc)
    else:
        raise AssertionError("expected signature failure")


def test_agent_identity_rejects_replay_and_endpoint_mismatch():
    payload = signed_identity()
    payload["issued_at"] = 100
    payload["expires_at"] = 110
    payload["signature"] = __import__("resolver_identity.crypto.signatures", fromlist=["sign_object"]).sign_object(payload, "agent-secret")
    try:
        verify_agent_identity_payload(payload, "agent-secret", now=200, expected_endpoint=ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    except ValueError as exc:
        assert "expired" in str(exc)
    else:
        raise AssertionError("expected replay expiry failure")

    fresh = signed_identity()
    try:
        verify_agent_identity_payload(fresh, "agent-secret", expected_endpoint=ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    except ValueError as exc:
        assert "endpoint" in str(exc)
    else:
        raise AssertionError("expected endpoint mismatch")


def test_parse_agent_base_urls_supports_ip_and_endpoint_keys():
    parsed = parse_agent_base_urls("192.0.2.53=http://agent-r1:8010,192.0.2.54:53:udp=http://agent-r2:8010")
    assert parsed["192.0.2.53"] == "http://agent-r1:8010"
    assert parsed["192.0.2.54:53:udp"] == "http://agent-r2:8010"


def signed_identity_ed25519(resolver_id="operator-a/r1", endpoint_ip="192.0.2.53", upstream_ip="192.0.2.54", config_version="1", private_key=R1_AGENT_PRIVATE):
    return build_agent_identity_ed25519(
        resolver_id=resolver_id,
        endpoint=ResolverEndpoint(ip=endpoint_ip, port=53, transport="udp"),
        upstreams=[ResolverEndpoint(ip=upstream_ip, port=53, transport="udp")] if upstream_ip else [],
        config_version=config_version,
        private_key_b64=private_key,
        max_age_seconds=30,
    )


class FakeAgentProvider(AgentResolverChainProvider):
    def __init__(self, payloads, secret="agent-secret", agent_base_urls=None, **kwargs):
        kwargs.setdefault("distributed_verification", False)
        super().__init__(agent_base_urls or {"192.0.2.53": "mock://r1"}, signature_secret=secret, **kwargs)
        self.payloads = list(payloads)
        self.calls = 0

    def _fetch_identity(self, base_url):
        self.calls += 1
        if not self.payloads:
            raise RuntimeError("agent unavailable")
        item = self.payloads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeDistributedAgentProvider(AgentResolverChainProvider):
    def __init__(self, payloads, secret="agent-secret", agent_base_urls=None, **kwargs):
        kwargs.setdefault("distributed_verification", True)
        super().__init__(agent_base_urls or {"192.0.2.53": "mock://r1"}, signature_secret=secret, **kwargs)
        self.payloads = list(payloads)
        self.calls = 0

    def _fetch_verification_chain(self, base_url):
        self.calls += 1
        if not self.payloads:
            raise RuntimeError("agent unavailable")
        item = self.payloads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def signed_hop(from_resolver_id, from_ip, upstream_ip, verification, private_key):
    hop = HopVerificationResult.from_verification_result(
        from_resolver_id=from_resolver_id,
        from_endpoint=ResolverEndpoint(ip=from_ip, port=53, transport="udp"),
        upstream_endpoint=ResolverEndpoint(ip=upstream_ip, port=53, transport="udp"),
        verification=verification,
        max_age_seconds=30,
    )
    sign_hop_verification_result(hop, private_key)
    return hop


def signed_chain(resolver_id, endpoint_ip, hops, private_key, downstream_chains=None, terminal_upstreams=None, config_version="1", chain_errors=None, final_result=True):
    chain = VerificationChain(
        resolver_id=resolver_id,
        endpoint=ResolverEndpoint(ip=endpoint_ip, port=53, transport="udp"),
        config_version=config_version,
        hops=hops,
        downstream_chains=downstream_chains or [],
        terminal_upstreams=terminal_upstreams or [],
        chain_errors=chain_errors or [],
        final_result=final_result,
    )
    return sign_verification_chain(chain, private_key)


def sign_existing_chain(payload, private_key):
    chain = VerificationChain.from_dict(payload)
    return sign_verification_chain(chain, private_key)


def base_distributed_payloads():
    stack = create_prototype_stack(signature_secret="secret", chain_provider=FakeDistributedAgentProvider([]))
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    publish(stack, "192.0.2.55", "operator-a/r3", R3_AGENT_PUBLIC)
    r2_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    r3_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp"))
    r3_chain_payload = signed_chain(
        "operator-a/r3",
        "192.0.2.55",
        [],
        R3_AGENT_PRIVATE,
        terminal_upstreams=[ResolverEndpoint(ip="198.51.100.53", port=53, transport="udp")],
    )
    r2_hop = signed_hop("operator-a/r2", "192.0.2.54", "192.0.2.55", r3_result, R2_AGENT_PRIVATE)
    r2_chain_payload = signed_chain(
        "operator-a/r2",
        "192.0.2.54",
        [r2_hop],
        R2_AGENT_PRIVATE,
        downstream_chains=[VerificationChain.from_dict(r3_chain_payload)],
    )
    r1_hop = signed_hop("operator-a/r1", "192.0.2.53", "192.0.2.54", r2_result, R1_AGENT_PRIVATE)
    r1_chain_payload = signed_chain("operator-a/r1", "192.0.2.53", [r1_hop], R1_AGENT_PRIVATE, downstream_chains=[VerificationChain.from_dict(r2_chain_payload)])
    return stack, r1_chain_payload, r2_chain_payload


async def run_distributed_payload(payload, stack=None, provider=None):
    provider = provider or FakeDistributedAgentProvider([payload])
    if stack is None:
        stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
        publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
        publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
        publish(stack, "192.0.2.55", "operator-a/r3", R3_AGENT_PUBLIC)
    else:
        stack.coordinator.chain_provider = provider
    return await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)


def assert_servfail(result):
    assert not result.accepted
    assert result.response != ORIGINAL_RESPONSE
    assert result.response[3] & 0x0F == 2


async def test_agent_provider_discovers_r1_r2_and_allows_when_both_registered():
    provider = FakeAgentProvider([signed_identity_ed25519()])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2")

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert result.accepted
    assert result.response == ORIGINAL_RESPONSE
    assert provider.get_context(UpstreamResolver("192.0.2.53")).observed_resolvers[1].ip == "192.0.2.54"


async def test_agent_provider_fails_closed_when_r1_or_r2_unregistered_or_agent_bad():
    r1_only = create_prototype_stack(signature_secret="secret", chain_provider=FakeAgentProvider([signed_identity_ed25519()]))
    publish(r1_only, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    missing_r2 = await r1_only.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not missing_r2.accepted
    assert missing_r2.response[3] & 0x0F == 2

    r2_only = create_prototype_stack(signature_secret="secret", chain_provider=FakeAgentProvider([signed_identity_ed25519()]))
    publish(r2_only, "192.0.2.54", "operator-a/r2")
    missing_r1 = await r2_only.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not missing_r1.accepted
    assert missing_r1.response[3] & 0x0F == 2

    bad_id = signed_identity_ed25519(resolver_id="operator-a/not-r1")
    bad_agent = create_prototype_stack(signature_secret="secret", chain_provider=FakeAgentProvider([bad_id]))
    publish(bad_agent, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(bad_agent, "192.0.2.54", "operator-a/r2")
    # Wrong resolver_id in signed Agent metadata must not be trusted as chain
    # discovery evidence for the observed first hop.
    result = await bad_agent.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not result.accepted
    assert result.response[3] & 0x0F == 2

    unavailable = create_prototype_stack(signature_secret="secret", chain_provider=FakeAgentProvider([RuntimeError("down")]))
    publish(unavailable, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    agent_down = await unavailable.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not agent_down.accepted
    assert agent_down.response[3] & 0x0F == 2


async def test_dns_response_not_released_if_any_resolver_authentication_fails():
    provider = FakeAgentProvider([signed_identity_ed25519()])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    obj = publish(stack, "192.0.2.54", "operator-a/r2")
    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert not result.accepted
    assert result.response != ORIGINAL_RESPONSE
    assert result.response[3] & 0x0F == 2


async def test_hot_cache_query_does_not_repeat_indexer_access_but_still_checks_agent():
    provider = FakeAgentProvider([signed_identity_ed25519(), signed_identity_ed25519()])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2")
    first = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert first.accepted

    def unavailable(*args, **kwargs):
        raise AssertionError("hot cache should not use indexer cold path")

    stack.indexer.lookup = unavailable
    second = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert second.accepted
    assert provider.calls == 2


async def test_config_version_change_invalidates_old_chain_cache():
    provider = FakeAgentProvider([
        signed_identity_ed25519(config_version="1", upstream_ip="192.0.2.54"),
        signed_identity_ed25519(config_version="2", upstream_ip="192.0.2.55"),
    ])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2")
    publish(stack, "192.0.2.55", "operator-a/r3")
    first = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert first.accepted
    assert all(row["status"] == "VERIFIED" for row in stack.trusted_cache_repository.list())

    second = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert second.accepted
    rows = stack.trusted_cache_repository.list()
    r2_rows = [row for row in rows if row["endpoint"]["ip"] == "192.0.2.54"]
    assert r2_rows and r2_rows[0]["status"] == "EXPIRED"


async def test_recursive_agent_discovery_r1_r2_r3_allows_response():
    provider = FakeAgentProvider(
        [
            signed_identity_ed25519(resolver_id="operator-a/r1", endpoint_ip="192.0.2.53", upstream_ip="192.0.2.54", private_key=R1_AGENT_PRIVATE),
            signed_identity_ed25519(resolver_id="operator-a/r2", endpoint_ip="192.0.2.54", upstream_ip="192.0.2.55", private_key=R2_AGENT_PRIVATE),
        ],
        agent_base_urls={"192.0.2.53": "mock://r1", "192.0.2.54": "mock://r2"},
    )
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    publish(stack, "192.0.2.55", "operator-a/r3")

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert result.accepted
    context = provider.get_context(UpstreamResolver("192.0.2.53"))
    assert [endpoint.ip for endpoint in context.observed_resolvers] == ["192.0.2.53", "192.0.2.54", "192.0.2.55"]
    assert provider.calls == 2


async def test_recursive_agent_discovery_rejects_loop():
    provider = FakeAgentProvider(
        [
            signed_identity_ed25519(resolver_id="operator-a/r1", endpoint_ip="192.0.2.53", upstream_ip="192.0.2.54", private_key=R1_AGENT_PRIVATE),
            signed_identity_ed25519(resolver_id="operator-a/r2", endpoint_ip="192.0.2.54", upstream_ip="192.0.2.53", private_key=R2_AGENT_PRIVATE),
        ],
        agent_base_urls={"192.0.2.53": "mock://r1", "192.0.2.54": "mock://r2"},
    )
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert not result.accepted
    assert result.response[3] & 0x0F == 2




async def test_distributed_agent_chain_r1_verifies_only_first_hop_and_accepts_signed_downstream_results():
    provider = FakeDistributedAgentProvider([])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    publish(stack, "192.0.2.55", "operator-a/r3", R3_AGENT_PUBLIC)
    r2_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    r3_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp"))
    r3_chain_payload = signed_chain(
        "operator-a/r3",
        "192.0.2.55",
        [],
        R3_AGENT_PRIVATE,
        terminal_upstreams=[ResolverEndpoint(ip="198.51.100.53", port=53, transport="udp")],
    )
    r2_hop = signed_hop("operator-a/r2", "192.0.2.54", "192.0.2.55", r3_result, R2_AGENT_PRIVATE)
    r2_chain_payload = signed_chain(
        "operator-a/r2",
        "192.0.2.54",
        [r2_hop],
        R2_AGENT_PRIVATE,
        downstream_chains=[VerificationChain.from_dict(r3_chain_payload)],
    )
    r1_hop = signed_hop("operator-a/r1", "192.0.2.53", "192.0.2.54", r2_result, R1_AGENT_PRIVATE)
    r1_chain_payload = signed_chain(
        "operator-a/r1",
        "192.0.2.53",
        [r1_hop],
        R1_AGENT_PRIVATE,
        downstream_chains=[VerificationChain.from_dict(r2_chain_payload)],
    )
    provider.payloads.append(r1_chain_payload)

    cold_calls = []
    original_lookup = stack.indexer.lookup

    def tracking_lookup(key):
        cold_calls.append(key)
        return original_lookup(key)

    stack.indexer.lookup = tracking_lookup
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert result.accepted
    assert result.response == ORIGINAL_RESPONSE
    context = provider.get_context(UpstreamResolver("192.0.2.53"))
    assert [endpoint.ip for endpoint in context.observed_resolvers] == ["192.0.2.53", "192.0.2.54", "192.0.2.55"]
    assert any(row["resolver_id"] == "operator-a/r1" for row in stack.trusted_cache_repository.list())


async def test_distributed_agent_chain_rejects_tampered_downstream_signature():
    provider = FakeDistributedAgentProvider([])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    publish(stack, "192.0.2.55", "operator-a/r3")
    r2_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    r3_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp"))
    r2_hop = signed_hop("operator-a/r2", "192.0.2.54", "192.0.2.55", r3_result, R2_AGENT_PRIVATE)
    r2_chain_payload = signed_chain("operator-a/r2", "192.0.2.54", [r2_hop], R2_AGENT_PRIVATE)
    r2_chain_payload["config_version"] = "tampered-after-signature"
    r1_hop = signed_hop("operator-a/r1", "192.0.2.53", "192.0.2.54", r2_result, R1_AGENT_PRIVATE)
    r1_chain_payload = signed_chain(
        "operator-a/r1",
        "192.0.2.53",
        [r1_hop],
        R1_AGENT_PRIVATE,
        downstream_chains=[VerificationChain.from_dict(r2_chain_payload)],
    )
    provider.payloads.append(r1_chain_payload)

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert not result.accepted
    assert result.response[3] & 0x0F == 2


async def test_distributed_agent_chain_rejects_loop_in_signed_hops():
    provider = FakeDistributedAgentProvider([])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    r2_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    r1_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    r2_hop = signed_hop("operator-a/r2", "192.0.2.54", "192.0.2.53", r1_result, R2_AGENT_PRIVATE)
    r2_chain_payload = signed_chain("operator-a/r2", "192.0.2.54", [r2_hop], R2_AGENT_PRIVATE)
    r1_hop = signed_hop("operator-a/r1", "192.0.2.53", "192.0.2.54", r2_result, R1_AGENT_PRIVATE)
    r1_chain_payload = signed_chain(
        "operator-a/r1",
        "192.0.2.53",
        [r1_hop],
        R1_AGENT_PRIVATE,
        downstream_chains=[VerificationChain.from_dict(r2_chain_payload)],
    )
    provider.payloads.append(r1_chain_payload)

    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)

    assert_servfail(result)


async def test_wrapper_only_configures_first_hop_agent_url():
    provider = FakeDistributedAgentProvider([RuntimeError("should not reach")], agent_base_urls={"192.0.2.53": "mock://r1"})
    assert provider._agent_url_for(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")) == "mock://r1"
    assert provider._agent_url_for(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp")) is None
    assert provider._agent_url_for(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp")) is None


async def test_tampered_r1_verification_chain_signature_fails_closed():
    _stack, payload, _r2_payload = base_distributed_payloads()
    payload["config_version"] = "tampered"
    result = await run_distributed_payload(payload)
    assert_servfail(result)


@pytest.mark.parametrize(
    "path,value",
    [
        (("hops", 0, "upstream_resolver_id"), "operator-a/evil"),
        (("hops", 0, "evidence", "object_hash"), "0x" + "11" * 32),
        (("hops", 0, "evidence", "state_root"), "0x" + "22" * 32),
        (("hops", 0, "evidence", "resolver_status"), "REVOKED"),
        (("hops", 0, "evidence", "root_status"), "REVOKED"),
        (("hops", 0, "evidence", "endpoint_binding_status"), "MISMATCH"),
        (("hops", 0, "evidence", "upstream_type"), "authoritative_boundary"),
    ],
)
async def test_tampered_r1_signed_hop_or_evidence_fails_closed(path, value):
    _stack, payload, _r2_payload = base_distributed_payloads()
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)
    result = await run_distributed_payload(payload)
    assert_servfail(result)


async def test_tampered_r2_downstream_hop_endpoint_fails_closed():
    _stack, payload, _r2_payload = base_distributed_payloads()
    r2_chain = payload["downstream_chains"][0]
    r2_chain["hops"][0]["upstream_endpoint"] = {"ip": "192.0.2.99", "port": 53, "transport": "udp"}
    payload["downstream_chains"][0] = sign_existing_chain(r2_chain, R2_AGENT_PRIVATE)
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)
    result = await run_distributed_payload(payload)
    assert_servfail(result)


async def test_expired_signed_hop_fails_closed():
    _stack, payload, _r2_payload = base_distributed_payloads()
    hop = payload["hops"][0]
    hop["issued_at"] = int(time.time()) - 100
    hop["expires_at"] = int(time.time()) - 50
    hop["evidence"]["checked_at"] = hop["issued_at"]
    hop["evidence"]["expires_at"] = hop["expires_at"]
    hop_obj = HopVerificationResult.from_dict(hop)
    sign_hop_verification_result(hop_obj, R1_AGENT_PRIVATE)
    payload["hops"][0] = hop_obj.to_dict()
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)
    result = await run_distributed_payload(payload)
    assert_servfail(result)


async def test_config_version_rollback_or_replay_fails_closed():
    stack, payload_v2, _ = base_distributed_payloads()
    provider = FakeDistributedAgentProvider([payload_v2])
    stack.coordinator.chain_provider = provider
    first = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert first.accepted

    payload_v1 = copy.deepcopy(payload_v2)
    payload_v1["config_version"] = "0"
    payload_v1 = sign_existing_chain(payload_v1, R1_AGENT_PRIVATE)
    provider.payloads.append(payload_v1)
    second = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert_servfail(second)


async def test_signed_chain_exceeding_max_depth_fails_closed():
    _stack, payload, _ = base_distributed_payloads()
    provider = FakeDistributedAgentProvider([payload], max_depth=1)
    result = await run_distributed_payload(payload, provider=provider)
    assert_servfail(result)


async def test_downstream_agent_failures_are_reported_as_failed_chain_not_success():
    provider = FakeDistributedAgentProvider([RuntimeError("agent unavailable")])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert_servfail(result)


async def test_agent_indexer_or_registry_failure_without_cache_fails_closed():
    provider = FakeAgentProvider([signed_identity_ed25519()])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2")
    stack.indexer.lookup = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("indexer down"))
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert_servfail(result)

    provider = FakeAgentProvider([signed_identity_ed25519()])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=provider)
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2")
    stack.registry.get_endpoint_binding = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("registry down"))
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert_servfail(result)


async def test_terminal_upstream_ends_chain_without_identity_verification():
    r2_chain = VerificationChain(
        resolver_id="operator-a/r2",
        endpoint=ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"),
        config_version="1",
        terminal_upstreams=[ResolverEndpoint(ip="198.51.100.53", port=53, transport="udp")],
        final_result=True,
    )
    r2_chain_payload = sign_verification_chain(r2_chain, R2_AGENT_PRIVATE)
    stack = create_prototype_stack(signature_secret="secret", chain_provider=FakeDistributedAgentProvider([]))
    publish(stack, "192.0.2.53", "operator-a/r1", R1_AGENT_PUBLIC)
    publish(stack, "192.0.2.54", "operator-a/r2", R2_AGENT_PUBLIC)
    r2_result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    r1_hop = signed_hop("operator-a/r1", "192.0.2.53", "192.0.2.54", r2_result, R1_AGENT_PRIVATE)
    payload = signed_chain("operator-a/r1", "192.0.2.53", [r1_hop], R1_AGENT_PRIVATE, downstream_chains=[VerificationChain.from_dict(r2_chain_payload)])
    result = await run_distributed_payload(payload, stack=stack)
    assert result.accepted
    context = stack.coordinator.chain_provider.get_context(UpstreamResolver("192.0.2.53"))
    assert "198.51.100.53" not in [endpoint.ip for endpoint in context.observed_resolvers]


async def test_dns_answer_is_not_leaked_when_chain_rejected():
    _stack, payload, _ = base_distributed_payloads()
    payload["final_result"] = False
    payload["chain_errors"] = ["forced failure"]
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)
    result = await run_distributed_payload(payload)
    assert_servfail(result)
