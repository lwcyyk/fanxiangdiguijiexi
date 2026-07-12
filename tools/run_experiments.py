from __future__ import annotations

import argparse
import asyncio
import json
import time

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.wrapper.query_processor import UpstreamResolver

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"


def publish_demo(stack, resolver_id="operator-a/resolver-01", ip="192.0.2.53", valid_until="2027-07-01T00:00:00Z"):
    obj = build_resolver_object(
        resolver_id,
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        valid_until,
    )
    stack.publisher.publish(obj)
    return obj


def functional_closure():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    obj = publish_demo(stack)
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    return {"experiment": "functional_closure", "accepted": result.accepted, "result": result.to_dict(), "resolver_id": obj.resolver_id}


def malicious_resolver_injection():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    publish_demo(stack, ip="192.0.2.53")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="198.51.100.53", port=53, transport="udp"))
    return {"experiment": "malicious_resolver_injection", "accepted": result.accepted, "expected": "reject", "result": result.to_dict()}


def offchain_tampering():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    obj = publish_demo(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    data = json.loads(row["object_json"])
    data["operator"]["name"] = "Tampered Operator"
    stack.conn.execute("UPDATE resolver_objects SET object_json=? WHERE resolver_id=?", (json.dumps(data), obj.resolver_id))
    stack.conn.commit()
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    return {"experiment": "offchain_tampering", "accepted": result.accepted, "expected": "reject_hash_mismatch", "result": result.to_dict()}


def replay_object():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    obj = publish_demo(stack)
    stack.conn.execute("UPDATE registry_anchors SET object_version=? WHERE resolver_id_key=?", (2, resolver_id_key(obj.resolver_id)))
    stack.conn.commit()
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    return {"experiment": "replay_object", "accepted": result.accepted, "expected": "reject_version_mismatch", "result": result.to_dict()}


def cold_hot_cache(iterations: int = 25):
    stack = create_prototype_stack(signature_secret="experiment-secret")
    publish_demo(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    start = time.perf_counter()
    cold = stack.verifier.verify_endpoint(endpoint)
    cold_ms = (time.perf_counter() - start) * 1000
    hot_ms = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = stack.verifier.verify_endpoint(endpoint)
        hot_ms.append((time.perf_counter() - start) * 1000)
        assert result.accepted
    return {
        "experiment": "cold_hot_cache",
        "cold_accepted": cold.accepted,
        "cold_ms": cold_ms,
        "hot_avg_ms": sum(hot_ms) / len(hot_ms),
        "hot_min_ms": min(hot_ms),
        "hot_max_ms": max(hot_ms),
        "iterations": iterations,
    }


def revocation_propagation():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    obj = publish_demo(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    before = stack.verifier.verify_endpoint(endpoint)
    start = time.perf_counter()
    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    stack.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    after = stack.verifier.verify_endpoint(endpoint)
    propagation_ms = (time.perf_counter() - start) * 1000
    return {"experiment": "revocation_propagation", "before_accepted": before.accepted, "after_accepted": after.accepted, "propagation_ms": propagation_ms, "after": after.to_dict()}


def root_revocation():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    obj = publish_demo(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    stack.registry.publish_root(row["state_root"], "REVOKED")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    return {"experiment": "root_revocation", "accepted": result.accepted, "expected": "reject_root_status_invalid", "result": result.to_dict()}


async def multi_resolver_parallel():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    publish_demo(stack, resolver_id="operator-a/r1", ip="192.0.2.53")
    publish_demo(stack, resolver_id="operator-a/r2", ip="192.0.2.54")

    async def forwarder(query, host, port):
        return RESPONSE

    result = await stack.processor.process(
        QUERY,
        [UpstreamResolver("192.0.2.53", observed_resolvers=[ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp")])],
        forwarder,
    )
    journal = stack.journal.get(result.request_id)
    return {"experiment": "multi_resolver_parallel", "accepted": result.accepted, "request_id": result.request_id, "journal": journal}


def out_of_band_failure():
    stack = create_prototype_stack(signature_secret="experiment-secret")
    publish_demo(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    cold = stack.verifier.verify_endpoint(endpoint)

    def unavailable(*args, **kwargs):
        raise ConnectionError("out-of-band unavailable")

    stack.indexer.lookup = unavailable
    stack.registry.get_endpoint_binding = unavailable
    hot = stack.verifier.verify_endpoint(endpoint)

    for row in stack.cache.memory.values():
        row["hard_expire_at"] = "2020-01-01T00:00:00Z"
    expired = stack.verifier.verify_endpoint(endpoint)
    return {"experiment": "out_of_band_failure", "cold": cold.to_dict(), "hot_with_oob_down": hot.to_dict(), "expired_cache_with_oob_down": expired.to_dict()}


EXPERIMENTS = {
    "functional": functional_closure,
    "malicious": malicious_resolver_injection,
    "tamper": offchain_tampering,
    "replay": replay_object,
    "cache": cold_hot_cache,
    "revoke": revocation_propagation,
    "root-revoke": root_revocation,
    "multi": multi_resolver_parallel,
    "oob": out_of_band_failure,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run resolver identity prototype experiments")
    parser.add_argument("experiment", choices=["all", *EXPERIMENTS.keys()])
    parser.add_argument("--iterations", type=int, default=25)
    args = parser.parse_args()
    names = list(EXPERIMENTS) if args.experiment == "all" else [args.experiment]
    results = []
    for name in names:
        if name == "cache":
            results.append(EXPERIMENTS[name](args.iterations))
        elif name == "multi":
            results.append(asyncio.run(EXPERIMENTS[name]()))
        else:
            results.append(EXPERIMENTS[name]())
    print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
