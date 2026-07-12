import sqlite3
from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.chain.registry_client import SQLiteRegistryClient
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.db.schema import init_db
from resolver_identity.db.repositories import IndexerRepository, RegistryRepository, TrustedCacheRepository
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier


def make_stack(secret="secret"):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    indexer = IndexerRepository(conn)
    registry = SQLiteRegistryClient(RegistryRepository(conn))
    cache = CacheManager(TrustedCacheRepository(conn))
    verifier = ResolverVerifier(indexer, registry, cache, VerificationPolicy({"udp", "tcp", "doh"}), secret)
    publisher = AdminPublisher(indexer, registry, secret)
    return conn, publisher, verifier, registry


def test_valid_resolver_passes_and_uses_cache():
    _, publisher, verifier, _ = make_stack()
    obj = build_resolver_object("operator-a/resolver-01", "operator-a", "Operator A", [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}], "2026-07-01T00:00:00Z", "2027-07-01T00:00:00Z")
    publisher.publish(obj)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    first = verifier.verify_endpoint(endpoint)
    assert first.accepted, first
    second = verifier.verify_endpoint(endpoint)
    assert second.accepted
    assert second.evidence["cache"] == "hit"


def test_unknown_resolver_fails_closed():
    _, _, verifier, _ = make_stack()
    result = verifier.verify_endpoint(ResolverEndpoint(ip="198.51.100.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["lookup_not_found"]


def test_revoked_resolver_fails_after_cache_invalidation():
    _, publisher, verifier, registry = make_stack()
    obj = build_resolver_object("operator-a/resolver-01", "operator-a", "Operator A", [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}], "2026-07-01T00:00:00Z", "2027-07-01T00:00:00Z")
    publisher.publish(obj)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    assert verifier.verify_endpoint(endpoint).accepted
    verifier.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    result = verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["cache_revoked"]
