from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.crypto.hashes import ip_lookup_key, name_lookup_key, object_hash, resolver_id_key
from resolver_identity.crypto.signatures import sign_object, verify_object_signature


def test_object_hash_ignores_signature():
    obj = build_resolver_object("operator-a/resolver-01", "operator-a", "Operator A", [{"ip": "192.0.2.53", "transport": "udp"}], "2026-07-01T00:00:00Z", "2027-07-01T00:00:00Z")
    unsigned = obj.to_dict(include_signature=False)
    signed = dict(unsigned)
    signed["signature"] = sign_object(unsigned, "secret")
    assert object_hash(unsigned) == object_hash(signed)
    assert verify_object_signature(signed, "secret")
    signed["operator"]["name"] = "Tampered"
    assert not verify_object_signature(signed, "secret")


def test_lookup_keys_are_normalized():
    assert ip_lookup_key("192.0.2.53") == ip_lookup_key("192.0.2.53")
    assert name_lookup_key("DNS.Example.") == name_lookup_key("dns.example")
    assert resolver_id_key("Operator-A/Resolver") == resolver_id_key("operator-a/resolver")
