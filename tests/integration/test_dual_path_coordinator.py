import json

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import object_hash, resolver_id_key
from resolver_identity.crypto.merkle import build_merkle_proof, merkle_leaf, merkle_root
from resolver_identity.db.repositories import AuditLogRepository
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.resolver_chain import ResolverChainProvider, StaticResolverChainProvider

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
ORIGINAL_RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"


async def forward_ok(query, host, port):
    return ORIGINAL_RESPONSE


def publish(stack, ip="192.0.2.53", resolver_id="operator-a/resolver-01", version=1):
    obj = build_resolver_object(
        resolver_id,
        "operator-a",
        "Operator A",
        [{"endpoint_id": f"udp-{version}", "ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
        object_version=version,
    )
    stack.publisher.publish(obj)
    return obj


def reanchor_current_object_without_resigning(stack, resolver_id):
    row = stack.indexer.get_resolver(resolver_id)
    data = json.loads(row["object_json"])
    new_hash = object_hash(data)
    rid_key = resolver_id_key(resolver_id)
    leaf = merkle_leaf(rid_key, new_hash, int(data["object_version"]), data["status"])
    proof = build_merkle_proof([leaf], 0)
    root = merkle_root([leaf])
    stack.conn.execute("UPDATE resolver_objects SET object_hash=?, state_root=? WHERE resolver_id=?", (new_hash, root, resolver_id))
    stack.conn.execute("UPDATE resolver_proofs SET leaf_hash=?, proof_json=?, state_root=? WHERE resolver_id=?", (leaf, json.dumps(proof), root, resolver_id))
    stack.conn.execute("UPDATE registry_anchors SET object_hash=?, state_root=? WHERE resolver_id_key=?", (new_hash, root, rid_key))
    stack.conn.execute("INSERT OR REPLACE INTO registry_roots(state_root,status) VALUES(?,?)", (root, "ACTIVE"))
    stack.conn.commit()


class EmptyProvider(ResolverChainProvider):
    def observed_resolvers(self, upstream):
        return []


async def test_single_resolver_cold_cache_allows_original_dns_response():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert result.accepted
    assert result.response == ORIGINAL_RESPONSE
    logs = AuditLogRepository(stack.conn).list(10)
    decisions = [log for log in logs if log["event_type"] == "QueryDecision"]
    assert decisions[0]["payload"]["qname"] == "example.com"
    assert decisions[0]["payload"]["qtype"] == "A"
    assert decisions[0]["payload"]["decision"] == "ALLOW"


async def test_hot_cache_does_not_repeat_indexer_or_registry_access():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    first = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert first.accepted

    def unavailable(*args, **kwargs):
        raise AssertionError("cold path should not be used on hot cache")

    stack.indexer.lookup = unavailable
    stack.registry.get_endpoint_binding = unavailable
    stack.registry.get_anchor = unavailable
    second = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert second.accepted
    assert second.response == ORIGINAL_RESPONSE


async def test_multi_resolver_all_pass_allows_response():
    chain_provider = StaticResolverChainProvider.from_config([{"ip": "192.0.2.54", "port": 53, "transport": "udp"}])
    stack = create_prototype_stack(signature_secret="secret", chain_provider=chain_provider)
    publish(stack, ip="192.0.2.53", resolver_id="operator-a/r1")
    publish(stack, ip="192.0.2.54", resolver_id="operator-a/r2")
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert result.accepted
    assert result.response == ORIGINAL_RESPONSE


async def test_signature_failure_returns_servfail_not_original_response():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    data = json.loads(row["object_json"])
    data["operator"]["name"] = "Tampered Operator"
    stack.conn.execute("UPDATE resolver_objects SET object_json=? WHERE resolver_id=?", (json.dumps(data), obj.resolver_id))
    stack.conn.commit()
    reanchor_current_object_without_resigning(stack, obj.resolver_id)
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not result.accepted
    assert result.response != ORIGINAL_RESPONSE
    assert result.response[3] & 0x0F == 2


async def test_merkle_proof_failure_returns_servfail():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish(stack)
    proof = stack.indexer.get_proof(obj.resolver_id)["proof"]
    proof["root"] = "0x" + "00" * 32
    stack.conn.execute("UPDATE resolver_proofs SET proof_json=? WHERE resolver_id=?", (json.dumps(proof), obj.resolver_id))
    stack.conn.commit()
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not result.accepted
    assert result.response != ORIGINAL_RESPONSE
    assert result.response[3] & 0x0F == 2


async def test_resolver_or_root_revoked_returns_servfail():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish(stack)
    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not result.accepted
    assert result.response[3] & 0x0F == 2

    stack2 = create_prototype_stack(signature_secret="secret")
    obj2 = publish(stack2)
    row = stack2.indexer.get_resolver(obj2.resolver_id)
    stack2.registry.publish_root(row["state_root"], "REVOKED")
    result2 = await stack2.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not result2.accepted
    assert result2.response[3] & 0x0F == 2


async def test_hard_ttl_expiry_forces_full_reverification():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    assert (await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)).accepted
    for row in stack.cache.memory.values():
        row["hard_expire_at"] = "2020-01-01T00:00:00Z"
    stack.conn.execute("UPDATE trusted_cache SET hard_expire_at='2020-01-01T00:00:00Z'")
    stack.conn.commit()
    calls = {"lookup": 0}
    original_lookup = stack.indexer.lookup

    def counted_lookup(*args, **kwargs):
        calls["lookup"] += 1
        return original_lookup(*args, **kwargs)

    stack.indexer.lookup = counted_lookup
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert result.accepted
    assert calls["lookup"] >= 1


async def test_endpoint_mismatch_and_no_observable_resolver_fail_closed():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, ip="192.0.2.53")
    mismatch = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.54")], forward_ok)
    assert not mismatch.accepted
    assert mismatch.response[3] & 0x0F == 2

    strict_stack = create_prototype_stack(signature_secret="secret", chain_provider=EmptyProvider())
    publish(strict_stack, ip="192.0.2.53")
    strict = await strict_stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert not strict.accepted
    assert strict.response[3] & 0x0F == 2


async def test_object_version_update_invalidates_old_cache_and_reverifies():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, version=1)
    assert (await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)).accepted
    publish(stack, version=2)
    stack.cache.invalidate_object_version("operator-a/resolver-01", 2)
    result = await stack.coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok)
    assert result.accepted
    cache_rows = stack.trusted_cache_repository.list()
    assert any(row["object_version"] == 2 and row["status"] == "VERIFIED" for row in cache_rows)
