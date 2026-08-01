import json
import time
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


def test_norn_snapshot_reuses_plan_root_and_has_pinned_schema():
    plan = build_plan(
        [
            {
                "server_id": "operator/r1",
                "endpoints": [
                    {"ip": "192.0.2.53", "port": 53, "transport": "udp"}
                ],
                "object_version": 1,
                "valid_until": int(time.time()) + 7_200,
                "status": "ACTIVE",
            }
        ],
        root_version=1,
        chain_id=31337,
        contract_address="0x" + "11" * 20,
        contract_code_hash="0x" + "22" * 32,
    )
    snapshot = manage.build_norn_snapshot(
        plan,
        chain_id=20_001,
        genesis_block_hash="0x" + "33" * 32,
        registry_address="0x" + "44" * 20,
        registry_key="resolver-identity-registry-v2",
        snapshot_version=1,
        checkpoint_height=100,
        checkpoint_hash="0x" + "55" * 32,
        valid_until=int(time.time()) + 3_600,
        issuer="norn-registry",
        key_id="snapshot-key-1",
    )

    assert snapshot["state_root"] == plan["state_root"]
    assert snapshot["registry_schema_hash"] == manage.NORN_REGISTRY_SCHEMA_HASH_V1
    assert snapshot["entries"][0]["resolver_id_key"] == plan["entries"][0][
        "resolver_id_key"
    ]
    with pytest.raises(ValueError, match="32-byte"):
        manage.build_norn_snapshot(
            plan,
            chain_id=20_001,
            genesis_block_hash="0x12",
            registry_address="0x" + "44" * 20,
            registry_key="resolver-identity-registry-v2",
            snapshot_version=1,
            checkpoint_height=100,
            checkpoint_hash="0x" + "55" * 32,
            valid_until=int(time.time()) + 3_600,
            issuer="norn-registry",
            key_id="snapshot-key-1",
        )


def test_external_snapshot_reuses_plan_and_pins_native_target():
    plan = build_plan(
        [
            {
                "server_id": "operator/r1",
                "endpoints": [
                    {"ip": "192.0.2.53", "port": 53, "transport": "udp"}
                ],
                "object_version": 1,
                "valid_until": int(time.time()) + 7_200,
                "status": "ACTIVE",
            }
        ],
        root_version=1,
        chain_id=31337,
        contract_address="0x" + "11" * 20,
        contract_code_hash="0x" + "22" * 32,
    )
    snapshot = manage.build_external_snapshot(
        plan,
        driver="fabric",
        chain_identity="fabric:channel-a:genesis-abc",
        registry_locator="fabric:channel-a/identity-registry",
        registry_schema_hash="0x" + "44" * 32,
        generation=7,
        checkpoint_height=100,
        checkpoint_hash="0x" + "55" * 32,
        valid_until=int(time.time()) + 3_600,
        issuer="adapter-operator",
        key_id="adapter-key-1",
    )

    assert snapshot["state_root"] == plan["state_root"]
    assert snapshot["target"]["adapter"] == "external"
    assert snapshot["target"]["adapter_metadata"] == {
        "adapter_type": "external",
        "driver": "fabric",
        "snapshot_signer_issuer": "adapter-operator",
        "snapshot_signer_key_id": "adapter-key-1",
    }
    assert snapshot["target"]["registry_schema_hash"] == "0x" + "44" * 32
    assert "chain_id" not in snapshot["target"]
    assert "contract_address" not in snapshot["target"]
    assert "contract_code_hash" not in snapshot["target"]
    assert snapshot["checkpoint"]["number"] == 100
    assert snapshot["checkpoint"]["finality_type"] == "external-signed-checkpoint"
    snapshot["target"]["chain_id"] = 30_001
    with pytest.raises(ValueError, match="required fields"):
        manage.validate_external_snapshot_shape(snapshot)


def test_external_snapshot_rejects_metadata_confusion_and_field_overflow():
    plan = build_plan(
        [
            {
                "server_id": "operator/r1",
                "endpoints": [
                    {"ip": "192.0.2.53", "port": 53, "transport": "udp"}
                ],
                "object_version": 1,
                "valid_until": int(time.time()) + 7_200,
                "status": "ACTIVE",
            }
        ],
        root_version=1,
        chain_id=31337,
        contract_address="0x" + "11" * 20,
        contract_code_hash="0x" + "22" * 32,
    )
    snapshot = manage.build_external_snapshot(
        plan,
        driver="fabric",
        chain_identity="fabric:channel-a:genesis-abc",
        registry_locator="fabric:channel-a/identity-registry",
        registry_schema_hash="0x" + "44" * 32,
        generation=7,
        checkpoint_height=100,
        checkpoint_hash="0x" + "55" * 32,
        valid_until=int(time.time()) + 3_600,
        issuer="adapter-operator",
        key_id="adapter-key-1",
    )

    snapshot["target"]["adapter_metadata"]["adapter_type"] = "evm"
    with pytest.raises(ValueError, match="required fields"):
        manage.validate_external_snapshot_shape(snapshot)

    snapshot["target"]["adapter_metadata"]["adapter_type"] = "external"
    snapshot["entries"][0]["server_id"] = "x" * 257
    with pytest.raises(ValueError, match="entry values"):
        manage.validate_external_snapshot_shape(snapshot)


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


def test_transaction_evidence_requires_complete_receipt():
    receipt = {
        "transactionHash": "0x" + "11" * 32,
        "from": "0x" + "22" * 20,
        "blockNumber": 10,
        "blockHash": "0x" + "33" * 32,
        "status": 1,
        "gasUsed": 12345,
    }
    assert manage.transaction_evidence(
        receipt,
        "ROOT_PUBLISHER_ROLE",
        "publish-root",
        "0x" + "44" * 32,
    ) == {
        "transaction_hash": "0x" + "11" * 32,
        "sender": "0x" + "22" * 20,
        "role": "ROOT_PUBLISHER_ROLE",
        "block_number": 10,
        "block_hash": "0x" + "33" * 32,
        "status": 1,
        "gas_used": 12345,
        "operation": "publish-root",
        "target_object": "0x" + "44" * 32,
    }
    with pytest.raises(ValueError, match="missing fields"):
        manage.transaction_evidence({}, "role", "operation", "target")


def test_receipt_journal_is_incremental_and_plan_bound(tmp_path):
    path = tmp_path / "receipts.json"
    first = manage.ReceiptJournal(path, "publish-root", "0x" + "11" * 32)
    first.append({"transaction_hash": "0x" + "22" * 32})
    first.append({"transaction_hash": "0x" + "22" * 32})
    assert len(json.loads(path.read_text())["transactions"]) == 1

    resumed = manage.ReceiptJournal(path, "publish-root", "0x" + "11" * 32)
    assert len(resumed.transactions) == 1
    with pytest.raises(ValueError, match="phase and plan"):
        manage.ReceiptJournal(path, "publish-root", "0x" + "33" * 32)
