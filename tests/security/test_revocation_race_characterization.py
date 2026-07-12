from __future__ import annotations

import threading

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.models.endpoint import ResolverEndpoint


def publish(stack):
    obj = build_resolver_object(
        "operator-a/race",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.88", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    return obj, ResolverEndpoint(ip="192.0.2.88", port=53, transport="udp")


def test_hot_cache_read_racing_revocation_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj, endpoint = publish(stack)
    assert stack.verifier.verify_endpoint(endpoint).accepted

    loaded = threading.Event()
    resume = threading.Event()
    original_get = stack.trusted_cache_repository.get_by_endpoint_lookup_key

    def blocked_get(endpoint_key):
        row = original_get(endpoint_key)
        loaded.set()
        assert resume.wait(3)
        return row

    stack.trusted_cache_repository.get_by_endpoint_lookup_key = blocked_get
    outcome = {}

    def verify():
        outcome["result"] = stack.verifier.verify_endpoint(endpoint)

    thread = threading.Thread(target=verify)
    thread.start()
    assert loaded.wait(3)
    stack.registry.revoke_resolver(__import__("resolver_identity.crypto.hashes", fromlist=["resolver_id_key"]).resolver_id_key(obj.resolver_id))
    stack.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    resume.set()
    thread.join(3)

    assert not thread.is_alive()
    assert not outcome["result"].accepted
    rows = stack.trusted_cache_repository.list()
    assert not rows or rows[0]["status"] == "REVOKED"


def test_cold_verification_cannot_store_verified_after_concurrent_revocation():
    stack = create_prototype_stack(signature_secret="secret")
    obj, endpoint = publish(stack)
    entered_store = threading.Event()
    resume = threading.Event()
    original_store = stack.cache.store_verified

    def blocked_store(*args, **kwargs):
        entered_store.set()
        assert resume.wait(3)
        return original_store(*args, **kwargs)

    stack.cache.store_verified = blocked_store
    outcome = {}

    def verify():
        outcome["result"] = stack.verifier.verify_endpoint(endpoint)

    thread = threading.Thread(target=verify)
    thread.start()
    assert entered_store.wait(3)
    stack.registry.revoke_resolver(__import__("resolver_identity.crypto.hashes", fromlist=["resolver_id_key"]).resolver_id_key(obj.resolver_id))
    stack.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    resume.set()
    thread.join(3)

    assert not thread.is_alive()
    assert not outcome["result"].accepted
    rows = stack.trusted_cache_repository.list()
    assert not rows or rows[0]["status"] == "REVOKED"
