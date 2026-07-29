import json
from types import SimpleNamespace

import pytest

import tools.manage_v2_registry as manage
from tools.manage_v2_registry import build_plan, load_plan


def test_publication_plan_is_stable_and_requires_approved_hash(tmp_path):
    identities = [
        {
            "schema_version": "dns-server-identity-v2",
            "server_id": "operator/r1",
            "endpoints": [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
            "object_version": 1,
            "valid_until": 1_900_000_000,
            "status": "ACTIVE",
        }
    ]
    plan = build_plan(
        identities,
        root_version=1,
        chain_id=31337,
        contract_address="0x" + "11" * 20,
        contract_code_hash="0x" + "22" * 32,
    )
    path = tmp_path / "plan.json"
    path.write_text(__import__("json").dumps(plan), encoding="utf-8")

    assert load_plan(path, plan["plan_hash"]) == plan
    try:
        load_plan(path, "0x" + "00" * 32)
    except ValueError as error:
        assert "approved hash" in str(error)
    else:
        raise AssertionError("unapproved plan hash was accepted")

    backend = SimpleNamespace(
        config=SimpleNamespace(
            chain_id=31337,
            contract_address="0x" + "11" * 20,
        ),
        contract_code_hash="0x" + "22" * 32,
    )
    manage.verify_plan_target(backend, plan)
    backend.config.chain_id = 1
    with pytest.raises(ValueError, match="live Registry"):
        manage.verify_plan_target(backend, plan)


def test_identity_set_rejects_cross_server_endpoint_conflict(tmp_path, monkeypatch):
    first = {
        "server_id": "operator/r1",
        "endpoints": [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
    }
    second = {
        "server_id": "operator/r2",
        "endpoints": [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
    }
    artifact = tmp_path / "identities.json"
    artifact.write_text(
        json.dumps({"identities": [first, second]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(manage.IssuerKeyRegistry, "from_file", lambda _: object())
    monkeypatch.setattr(manage, "validate_identity", lambda *_: None)

    with pytest.raises(ValueError, match="shared by"):
        manage.load_identities(artifact, tmp_path / "issuer-keys.json")


def test_plan_diff_requires_explicit_endpoint_unbind_and_resolver_revocation():
    target = {
        "chain_id": 31337,
        "contract_address": "0x" + "11" * 20,
        "contract_code_hash": "0x" + "22" * 32,
    }
    previous = build_plan(
        [
            {
                "server_id": "operator/r1",
                "endpoints": [
                    {"ip": "192.0.2.51", "port": 53, "transport": "udp"},
                    {"ip": "192.0.2.52", "port": 53, "transport": "udp"},
                ],
                "object_version": 1,
                "valid_until": 1_900_000_000,
                "status": "ACTIVE",
            },
            {
                "server_id": "operator/r2",
                "endpoints": [
                    {"ip": "192.0.2.53", "port": 53, "transport": "udp"}
                ],
                "object_version": 1,
                "valid_until": 1_900_000_000,
                "status": "ACTIVE",
            },
        ],
        root_version=1,
        **target,
    )
    current = build_plan(
        [
            {
                "server_id": "operator/r1",
                "endpoints": [
                    {"ip": "192.0.2.52", "port": 53, "transport": "udp"},
                    {"ip": "192.0.2.54", "port": 53, "transport": "udp"},
                ],
                "object_version": 2,
                "valid_until": 1_900_000_100,
                "status": "ACTIVE",
            }
        ],
        root_version=2,
        previous_plan=previous,
        **target,
    )

    assert current["previous_plan_hash"] == previous["plan_hash"]
    assert {item["server_id"] for item in current["resolver_revocations"]} == {
        "operator/r2"
    }
    assert len(current["endpoint_unbinds"]) == 2


def test_removal_actions_are_idempotent_and_owner_checked():
    plan = {
        "endpoint_unbinds": [
            {
                "endpoint_key": "old-endpoint",
                "resolver_id_key": "resolver-r1",
                "server_id": "operator/r1",
            }
        ],
        "resolver_revocations": [
            {"resolver_id_key": "resolver-r2", "server_id": "operator/r2"}
        ],
    }

    class Backend:
        bindings = {"old-endpoint": "resolver-r1"}
        revoked = []

        def get_endpoint_binding(self, key):
            return self.bindings.get(key)

        def unbind_endpoint(self, key):
            self.bindings.pop(key)

        def get_resolver_anchor(self, _key):
            return SimpleNamespace(status="ACTIVE")

        def revoke_resolver(self, key):
            self.revoked.append(key)

    backend = Backend()
    manage.unbind_endpoints(backend, plan)
    manage.unbind_endpoints(backend, plan)
    manage.revoke_removed_resolvers(backend, plan)
    assert backend.bindings == {}
    assert backend.revoked == ["resolver-r2"]

    backend.bindings["old-endpoint"] = "resolver-other"
    with pytest.raises(ValueError, match="owner conflict"):
        manage.unbind_endpoints(backend, plan)


def test_active_root_must_match_approved_version():
    plan = {"state_root": "0x" + "44" * 32, "root_version": 2}
    backend = SimpleNamespace(
        get_root_record=lambda _root: SimpleNamespace(status="ACTIVE", version=1)
    )
    with pytest.raises(ValueError, match="Root version"):
        manage.publish_root(backend, plan)
