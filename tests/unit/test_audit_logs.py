from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.db.repositories import AuditLogRepository


def test_publish_bind_revoke_are_audited():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    logs = AuditLogRepository(stack.conn).list(50)
    event_types = [row["event_type"] for row in logs]
    assert "ResolverPublished" in event_types
    assert "EndpointBound" in event_types
    assert "RootPublished" in event_types
    assert "ResolverRevoked" in event_types
