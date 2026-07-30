import copy
import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tools.manage_field_deployment as field
from resolver_identity.crypto.signatures import (
    generate_ed25519_keypair,
    sign_object_ed25519,
)
from tools.manage_v2_registry import build_plan


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _unit(tmp_path: Path, number: int) -> dict:
    link = f"L{number:02d}"
    material = tmp_path / "private" / f"{link}-r1-a"
    for index, name in enumerate(field.SECRET_FILES):
        value = base64.b64encode(bytes([number]) * 32).decode("ascii") if name == "agent_private_key" else f"{link}-{name}-{index}-" + chr(64 + number) * 48
        _write_private(
            material / "secrets" / name,
            value,
        )
    for index, name in enumerate(field.TLS_PRIVATE_FILES):
        _write_private(
            material / "tls" / name,
            f"test-tls-private-material-{link}-{name}-{index}-" + chr(70 + number) * 64,
        )
    for name in set(field.TLS_FILES) - set(field.TLS_PRIVATE_FILES):
        path = material / "tls" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"-----BEGIN CERTIFICATE-----\n{link}-{name}-" + chr(75 + number) * 64 + "\n-----END CERTIFICATE-----\n",
            encoding="utf-8",
        )
        path.chmod(0o644)
    return {
        "link_id": link,
        "unit_id": f"{link}-r1-a",
        "role": "entry",
        "hostname": f"ri-{link.lower()}-r1-01",
        "management_ip": f"10.20.{number}.11",
        "compose_project": f"ri-{link.lower()}-r1",
        "verification_mode": "public-hybrid",
        "agent_server_id": f"operator/{link}/r1",
        "agent_key_id": f"agent-key-{link}-r1",
        "trace_producer_uid": 10002,
        "trace_producer_gid": 10002,
        "trace_socket_host_dir": f"/run/resolver-identity/{link}-r1",
        "wrapper_ip": f"10.10.{number}.53",
        "dns_port": 1053,
        "resolver_upstreams": [
            f"udp://10.10.{number}.54:53",
            f"tcp://10.10.{number}.54:53",
        ],
        "agent_bind_address": f"10.20.{number}.11",
        "agent_port": 8443,
        "metrics_bind_address": f"10.20.{number}.11",
        "metrics_ports": {"wrapper": 9108, "registry": 9109, "trace": 9110},
        "remote_release_root": "/opt/resolver-identity",
        "private_material_dir": str(material),
        "shadow_test_name": "www.iana.org",
        "rollback_target": f"10.10.{number}.54:53",
    }


def _inventory(tmp_path: Path, unit_count: int = 2) -> dict:
    units = [_unit(tmp_path, number) for number in range(1, unit_count + 1)]
    issuer_private, issuer_public = generate_ed25519_keypair()
    identities_list = []
    for number, unit in enumerate(units, 1):
        agent_public = (
            Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        identity = {
            "schema_version": "dns-server-identity-v2",
            "server_id": unit["agent_server_id"],
            "operator_id": "operator",
            "role": "RECURSIVE",
            "endpoints": [
                {"ip": f"10.10.{number}.54", "port": 53, "transport": "udp"},
                {"ip": f"10.10.{number}.54", "port": 53, "transport": "tcp"},
            ],
            "anycast": False,
            "agent": {
                "key_id": unit["agent_key_id"],
                "algorithm": "ed25519",
                "public_key": base64.b64encode(agent_public).decode("ascii"),
                "service_url": (f"https://{unit['hostname']}.mgmt.internal.test:{unit['agent_port']}"),
            },
            "valid_from": 1_780_000_000,
            "valid_until": 1_900_000_000,
            "object_version": 1,
            "status": "ACTIVE",
            "issuer": "field-issuer",
            "key_id": "issuer-key-01",
        }
        identity["signature"] = sign_object_ed25519(identity, issuer_private)
        identities_list.append(identity)
    identities = {"identities": identities_list}
    identities_path = tmp_path / "identities-v2.json"
    identities_path.write_text(json.dumps(identities), encoding="utf-8")
    issuer_path = tmp_path / "issuer-keys.json"
    issuer_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "issuer": "field-issuer",
                        "key_id": "issuer-key-01",
                        "algorithm": "ed25519",
                        "public_key": issuer_public,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    contract_address = "0x" + "1" * 40
    runtime_code_hash = "0x" + "2" * 64
    plan = build_plan(
        identities_list,
        root_version=1,
        chain_id=11155111,
        contract_address=contract_address,
        contract_code_hash=runtime_code_hash,
    )
    plan_path = tmp_path / "registry-plan-v2.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    verification_path = tmp_path / "verification.json"
    verification_path.write_text(
        json.dumps(
            {
                "chain_id": 11155111,
                "contract_address": contract_address,
                "runtime_code_hash": runtime_code_hash,
                "checks": {name: True for name in field.REQUIRED_VERIFICATION_CHECKS},
                "finalized_block": 100,
                "finalized_block_hash": "0x" + "a" * 64,
                "primary_rpc_host": "rpc.internal.test",
                "verification_rpc_host": "verify-rpc.internal.test",
            }
        ),
        encoding="utf-8",
    )
    roles_path = tmp_path / "roles.json"
    roles_path.write_text(
        json.dumps(
            {
                "chain_id": 11155111,
                "contract_address": contract_address,
                "governance_address": "0x" + "3" * 40,
                "root_publisher_address": "0x" + "4" * 40,
                "resolver_publisher_address": "0x" + "5" * 40,
                "endpoint_manager_address": "0x" + "6" * 40,
                "revoker_address": "0x" + "7" * 40,
                "transactions": [
                    {
                        "status": 1,
                        "transaction_hash": f"0x{i:064x}",
                        "block_hash": f"0x{i + 8:064x}",
                        "block_number": i,
                    }
                    for i in range(1, 9)
                ],
                "finalized_verification": {
                    "admin_count": 1,
                    "block_number": 10,
                    "block_hash": "0x" + "b" * 64,
                    "primary_rpc_host": "rpc.internal.test",
                    "verification_rpc_host": "verify-rpc.internal.test",
                    "checks": {name: True for name in field.REQUIRED_ROLE_CHECKS},
                },
            }
        ),
        encoding="utf-8",
    )
    publication_path = tmp_path / "publication-transactions.json"
    publication_path.write_text(
        json.dumps(
            {
                "schema_version": "registry-publication-transactions-v1",
                "chain_id": 11155111,
                "contract_address": contract_address,
                "plan_hash": plan["plan_hash"],
                "completed_phases": sorted(field.REQUIRED_PUBLICATION_PHASES),
                "transactions": [
                    {
                        "status": 1,
                        "transaction_hash": "0x" + "8" * 64,
                        "block_hash": "0x" + "9" * 64,
                        "block_number": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return {
        "schema_version": 1,
        "site_id": "dns-center-a",
        "change_ticket": "CHG-2026-0730",
        "release": {
            "git_commit": "a" * 40,
            "image": "registry.internal.test/ri@sha256:" + "b" * 64,
        },
        "registry": {
            "network_name": "sepolia",
            "rpc_url": "https://rpc.internal.test/v1?key=private&tenant=field",
            "verification_rpc_url": "https://verify-rpc.internal.test/v1",
            "chain_id": 11155111,
            "contract_address": contract_address,
            "runtime_code_hash": runtime_code_hash,
            "fallback_confirmations": 12,
            "max_staleness_seconds": 15,
        },
        "artifacts": {
            "identities_file": str(identities_path),
            "issuer_keys_file": str(issuer_path),
            "registry_verification_file": str(verification_path),
            "roles_file": str(roles_path),
            "registry_plan_file": str(plan_path),
            "publication_transactions_file": str(publication_path),
        },
        "hub": {
            "management_host": "ri-hub-mgmt-01",
            "operations_host": "ri-hub-ops-01",
            "test_client_host": "ri-test-client-01",
            "prometheus_ip": "10.20.250.10",
            "log_collector_ip": "10.20.250.11",
            "bastion_ip": "10.20.250.12",
            "backup_target": "/encrypted/backup/field",
        },
        "units": units,
    }


def test_template_is_shape_checked_but_rejected_as_deployment():
    template = field.load_json(field.REPO_ROOT / "specs/domain-center-star-deployment/site-inventory.example.json")
    assert field.validate_inventory(template, template=True)["schema_version"] == 1
    with pytest.raises(field.InventoryError, match="placeholder"):
        field.validate_inventory(template, check_materials=False)


def test_rendered_units_are_isolated_and_checksum_verified(tmp_path):
    inventory = field.validate_inventory(_inventory(tmp_path))
    bundles = field.render_bundles(inventory, tmp_path / "rendered")

    assert len(bundles) == 2
    for bundle in bundles:
        field.verify_bundle(bundle)
        assert (bundle / "scripts/lib/common.sh").is_file()
        assert (bundle / "deploy/registry-evidence/registry-plan-v2.json").is_file()
        env_text = (bundle / "deploy/link/.env").read_text(encoding="utf-8")
        assert "RI_FIELD_AGENT_SERVICE_URL=https://" in env_text
        assert "RI_FIELD_SHADOW_TEST_NAME=www.iana.org" in env_text
        assert "RI_WEB3_RPC_URL='https://rpc.internal.test/v1?key=private&tenant=field'" in env_text
        metadata = json.loads((bundle / "metadata/unit.json").read_text(encoding="utf-8"))
        assert metadata["rpc_host"] == "rpc.internal.test"
        assert metadata["verification_rpc_host"] == "verify-rpc.internal.test"
        assert metadata["plan_hash"].startswith("0x")
        assert "key=private" not in json.dumps(metadata)

    first_secret = bundles[0] / "deploy/link/secrets/agent_wrapper_token"
    first_secret.chmod(0o600)
    first_secret.write_text("tampered", encoding="utf-8")
    with pytest.raises(field.InventoryError, match="checksum mismatch"):
        field.verify_bundle(bundles[0])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data["registry"].update(chain_id=1), "Mainnet"),
        (
            lambda data: data["units"][0].update(
                resolver_upstreams=[
                    "udp://10.10.1.53:53",
                    "tcp://10.10.1.54:53",
                ]
            ),
            "points back",
        ),
        (
            lambda data: data["release"].update(image="registry.internal.test/ri:latest"),
            "sha256 digest",
        ),
        (
            lambda data: data["units"][0].update(wrapper_ip="192.0.2.53"),
            "documentation address",
        ),
    ],
)
def test_unsafe_inventory_is_rejected(tmp_path, mutation, message):
    inventory = _inventory(tmp_path)
    mutation(inventory)
    with pytest.raises(field.InventoryError, match=message):
        field.validate_inventory(inventory)


def test_cross_link_secret_reuse_is_rejected(tmp_path):
    inventory = _inventory(tmp_path)
    first = Path(inventory["units"][0]["private_material_dir"])
    second = Path(inventory["units"][1]["private_material_dir"])
    (second / "secrets/agent_wrapper_token").write_bytes((first / "secrets/agent_wrapper_token").read_bytes())
    with pytest.raises(field.InventoryError, match="reuses secret"):
        field.validate_inventory(inventory)


def test_agent_private_key_must_match_signed_identity(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    material = Path(inventory["units"][0]["private_material_dir"])
    _write_private(
        material / "secrets/agent_private_key",
        base64.b64encode(b"\x7f" * 32).decode("ascii"),
    )
    with pytest.raises(field.InventoryError, match="does not match"):
        field.validate_inventory(inventory)


def test_publication_evidence_must_cover_every_phase(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    publication_path = Path(inventory["artifacts"]["publication_transactions_file"])
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    publication["completed_phases"].remove("revoke-removed")
    publication_path.write_text(json.dumps(publication), encoding="utf-8")
    with pytest.raises(field.InventoryError, match="phases are incomplete"):
        field.validate_inventory(inventory)


def test_registry_evidence_requires_every_fixed_check(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    verification_path = Path(inventory["artifacts"]["registry_verification_file"])
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    del verification["checks"]["runtime_bytecode_match"]
    verification_path.write_text(json.dumps(verification), encoding="utf-8")
    with pytest.raises(field.InventoryError, match="runtime_bytecode_match"):
        field.validate_inventory(inventory)


def test_publication_receipt_requires_finalized_block_evidence(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    publication_path = Path(inventory["artifacts"]["publication_transactions_file"])
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    del publication["transactions"][0]["block_hash"]
    publication_path.write_text(json.dumps(publication), encoding="utf-8")
    with pytest.raises(field.InventoryError, match="receipts are incomplete"):
        field.validate_inventory(inventory)


def test_registry_rpc_hosts_must_be_independent(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    inventory["registry"]["verification_rpc_url"] = "https://rpc.internal.test/independent-path"
    with pytest.raises(field.InventoryError, match="RPC hosts"):
        field.validate_inventory(inventory)


def test_peer_token_can_only_be_shared_inside_one_link(tmp_path):
    inventory = _inventory(tmp_path)
    second_unit = inventory["units"][1]
    second_unit["link_id"] = inventory["units"][0]["link_id"]
    first = Path(inventory["units"][0]["private_material_dir"])
    second = Path(second_unit["private_material_dir"])
    (second / "secrets/agent_peer_token").write_bytes((first / "secrets/agent_peer_token").read_bytes())
    field.validate_inventory(inventory)

    wrong_purpose = copy.deepcopy(inventory)
    second = Path(wrong_purpose["units"][1]["private_material_dir"])
    (second / "secrets/agent_wrapper_token").write_bytes((first / "secrets/agent_peer_token").read_bytes())
    with pytest.raises(field.InventoryError, match="different secret purposes|reuses secret"):
        field.validate_inventory(wrong_purpose)


def test_private_material_symlink_is_rejected(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    material = Path(inventory["units"][0]["private_material_dir"])
    target = material / "secrets/agent_wrapper_token"
    replacement = material / "secrets/replacement"
    replacement.write_bytes(target.read_bytes())
    replacement.chmod(0o600)
    target.unlink()
    target.symlink_to(replacement)
    with pytest.raises(field.InventoryError, match="symbolic link"):
        field.validate_inventory(inventory)


def test_tampered_identity_is_rejected_before_render(tmp_path):
    inventory = _inventory(tmp_path, unit_count=1)
    identity_path = Path(inventory["artifacts"]["identities_file"])
    document = json.loads(identity_path.read_text(encoding="utf-8"))
    document["identities"][0]["object_version"] = 2
    identity_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(field.InventoryError, match="signature"):
        field.validate_inventory(inventory)


def test_bundle_symlink_is_rejected_even_with_an_existing_manifest(tmp_path):
    inventory = field.validate_inventory(_inventory(tmp_path, unit_count=1))
    bundle = field.render_bundles(inventory, tmp_path / "rendered")[0]
    (bundle / "unexpected-link").symlink_to("/etc/hosts")
    with pytest.raises(field.InventoryError, match="symbolic links"):
        field.verify_bundle(bundle)
