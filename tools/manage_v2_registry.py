from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import time
from pathlib import Path
from typing import Callable

from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.chain.contract_loader import load_contract_abi
from resolver_identity.chain.web3_backend import Web3RegistryBackend, Web3RegistryConfig
from resolver_identity.common.config import load_settings
from resolver_identity.crypto.hashes import object_hash, resolver_id_key
from resolver_identity.crypto.keys import IssuerKeyRegistry
from resolver_identity.crypto.merkle import merkle_leaf, merkle_root
from resolver_identity.crypto.signatures import (
    sign_object_ed25519,
    verify_object_signature_with_registry,
)
from resolver_identity.models.endpoint import ResolverEndpoint

NORN_REGISTRY_SNAPSHOT_V1 = "resolver-identity-norn-registry-snapshot-v1"
EXTERNAL_REGISTRY_SNAPSHOT_V1 = "resolver-identity-external-registry-snapshot-v1"
NORN_REGISTRY_SCHEMA_HASH_V1 = (
    "0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare and apply DNS identity V2 Registry plans")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--input", required=True)
    sign.add_argument("--private-key-file", required=True)
    sign.add_argument("--output", required=True)

    verify_identities = subparsers.add_parser("verify-identities")
    verify_identities.add_argument("--identities", required=True)
    verify_identities.add_argument("--issuer-keys", required=True)

    norn = subparsers.add_parser("prepare-norn-snapshot")
    norn.add_argument("--plan", required=True)
    norn.add_argument("--expected-plan-hash", required=True)
    norn.add_argument("--chain-id", required=True, type=int)
    norn.add_argument("--genesis-block-hash", required=True)
    norn.add_argument("--registry-address", required=True)
    norn.add_argument("--registry-key", required=True)
    norn.add_argument("--snapshot-version", required=True, type=int)
    norn.add_argument("--checkpoint-height", required=True, type=int)
    norn.add_argument("--checkpoint-hash", required=True)
    norn.add_argument("--valid-until", required=True, type=int)
    norn.add_argument("--issuer", required=True)
    norn.add_argument("--key-id", required=True)
    norn.add_argument("--private-key-file", required=True)
    norn.add_argument("--issuer-keys", required=True)
    norn.add_argument("--output", required=True)

    verify_norn = subparsers.add_parser("verify-norn-snapshot")
    verify_norn.add_argument("--snapshot", required=True)
    verify_norn.add_argument("--issuer-keys", required=True)

    external = subparsers.add_parser("prepare-external-snapshot")
    external.add_argument("--plan", required=True)
    external.add_argument("--expected-plan-hash", required=True)
    external.add_argument("--driver", required=True)
    external.add_argument("--chain-identity", required=True)
    external.add_argument("--registry-locator", required=True)
    external.add_argument("--registry-schema-hash", required=True)
    external.add_argument("--generation", required=True, type=int)
    external.add_argument("--checkpoint-height", required=True, type=int)
    external.add_argument("--checkpoint-hash", required=True)
    external.add_argument("--valid-until", required=True, type=int)
    external.add_argument("--issuer", required=True)
    external.add_argument("--key-id", required=True)
    external.add_argument("--private-key-file", required=True)
    external.add_argument("--issuer-keys", required=True)
    external.add_argument("--output", required=True)

    verify_external = subparsers.add_parser("verify-external-snapshot")
    verify_external.add_argument("--snapshot", required=True)
    verify_external.add_argument("--issuer-keys", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--identities", required=True)
    prepare.add_argument("--issuer-keys", required=True)
    prepare.add_argument("--root-version", required=True, type=int)
    prepare.add_argument("--chain-id", required=True, type=int)
    prepare.add_argument("--contract-address", required=True)
    prepare.add_argument("--contract-code-hash", required=True)
    prepare.add_argument("--previous-plan")
    prepare.add_argument("--output", required=True)

    for command in (
        "publish-root",
        "publish-resolvers",
        "unbind-endpoints",
        "bind-endpoints",
        "revoke-removed",
    ):
        apply = subparsers.add_parser(command)
        apply.add_argument("--plan", required=True)
        apply.add_argument("--expected-plan-hash", required=True)
        apply.add_argument("--receipt-output")

    revoke_resolver = subparsers.add_parser("revoke-resolver")
    revoke_resolver.add_argument("--server-id", required=True)
    revoke_resolver.add_argument("--receipt-output")
    revoke_root = subparsers.add_parser("revoke-root")
    revoke_root.add_argument("--state-root", required=True)
    revoke_root.add_argument("--receipt-output")

    args = parser.parse_args()
    if args.command == "sign":
        sign_identities(Path(args.input), Path(args.private_key_file), Path(args.output))
        return
    if args.command == "verify-identities":
        identities = load_identities(
            Path(args.identities),
            Path(args.issuer_keys),
        )
        print(json.dumps({"verified_identity_count": len(identities)}))
        return
    if args.command == "prepare-norn-snapshot":
        snapshot = build_norn_snapshot(
            load_plan(Path(args.plan), args.expected_plan_hash),
            chain_id=args.chain_id,
            genesis_block_hash=args.genesis_block_hash,
            registry_address=args.registry_address,
            registry_key=args.registry_key,
            snapshot_version=args.snapshot_version,
            checkpoint_height=args.checkpoint_height,
            checkpoint_hash=args.checkpoint_hash,
            valid_until=args.valid_until,
            issuer=args.issuer,
            key_id=args.key_id,
        )
        private_key = Path(args.private_key_file).read_text(encoding="utf-8").strip()
        snapshot["signature"] = sign_object_ed25519(snapshot, private_key)
        keys = IssuerKeyRegistry.from_file(args.issuer_keys)
        if not verify_object_signature_with_registry(snapshot, keys):
            raise ValueError("new Norn snapshot does not verify with issuer bundle")
        write_json_atomic(Path(args.output), snapshot)
        print(
            json.dumps(
                {
                    "schema_version": snapshot["schema_version"],
                    "snapshot_version": snapshot["snapshot_version"],
                    "state_root": snapshot["state_root"],
                    "identity_count": len(snapshot["entries"]),
                    "checkpoint_height": snapshot["checkpoint_height"],
                }
            )
        )
        return
    if args.command == "verify-norn-snapshot":
        snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        validate_norn_snapshot_shape(snapshot)
        keys = IssuerKeyRegistry.from_file(args.issuer_keys)
        if not verify_object_signature_with_registry(snapshot, keys):
            raise ValueError("Norn snapshot signature verification failed")
        print(
            json.dumps(
                {
                    "verified": True,
                    "snapshot_version": snapshot["snapshot_version"],
                    "identity_count": len(snapshot["entries"]),
                }
            )
        )
        return
    if args.command == "prepare-external-snapshot":
        snapshot = build_external_snapshot(
            load_plan(Path(args.plan), args.expected_plan_hash),
            driver=args.driver,
            chain_identity=args.chain_identity,
            registry_locator=args.registry_locator,
            registry_schema_hash=args.registry_schema_hash,
            generation=args.generation,
            checkpoint_height=args.checkpoint_height,
            checkpoint_hash=args.checkpoint_hash,
            valid_until=args.valid_until,
            issuer=args.issuer,
            key_id=args.key_id,
        )
        private_key = Path(args.private_key_file).read_text(encoding="utf-8").strip()
        snapshot["signature"] = sign_object_ed25519(snapshot, private_key)
        keys = IssuerKeyRegistry.from_file(args.issuer_keys)
        if not verify_object_signature_with_registry(snapshot, keys):
            raise ValueError("new external snapshot does not verify with issuer bundle")
        write_json_atomic(Path(args.output), snapshot)
        print(
            json.dumps(
                {
                    "schema_version": snapshot["schema_version"],
                    "adapter": snapshot["target"]["adapter"],
                    "generation": snapshot["generation"],
                    "state_root": snapshot["state_root"],
                    "identity_count": len(snapshot["entries"]),
                    "checkpoint_height": snapshot["checkpoint"]["number"],
                }
            )
        )
        return
    if args.command == "verify-external-snapshot":
        snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        validate_external_snapshot_shape(snapshot)
        keys = IssuerKeyRegistry.from_file(args.issuer_keys)
        if not verify_object_signature_with_registry(snapshot, keys):
            raise ValueError("external snapshot signature verification failed")
        print(
            json.dumps(
                {
                    "verified": True,
                    "adapter": snapshot["target"]["adapter"],
                    "generation": snapshot["generation"],
                    "identity_count": len(snapshot["entries"]),
                }
            )
        )
        return
    if args.command == "prepare":
        previous_plan = (
            load_previous_plan(Path(args.previous_plan)) if args.previous_plan else None
        )
        plan = build_plan(
            load_identities(Path(args.identities), Path(args.issuer_keys)),
            args.root_version,
            args.chain_id,
            args.contract_address,
            args.contract_code_hash,
            previous_plan=previous_plan,
        )
        write_json_atomic(Path(args.output), plan)
        print(
            json.dumps(
                {
                    "plan_hash": plan["plan_hash"],
                    "state_root": plan["state_root"],
                    "root_version": plan["root_version"],
                    "identity_count": len(plan["entries"]),
                    "endpoint_count": sum(
                        len(entry["endpoint_keys"]) for entry in plan["entries"]
                    ),
                    "endpoint_unbind_count": len(plan["endpoint_unbinds"]),
                    "resolver_revocation_count": len(plan["resolver_revocations"]),
                }
            )
        )
        return

    if args.command == "revoke-resolver":
        backend = registry_backend()
        receipt = backend.revoke_resolver(resolver_id_key(args.server_id))
        write_receipts_if_requested(
            args.receipt_output,
            args.command,
            [
                transaction_evidence(
                    receipt,
                    "REVOKER_ROLE",
                    "revoke-resolver",
                    args.server_id,
                )
            ],
        )
        return
    if args.command == "revoke-root":
        backend = registry_backend()
        receipt = backend.revoke_root(args.state_root)
        write_receipts_if_requested(
            args.receipt_output,
            args.command,
            [
                transaction_evidence(
                    receipt,
                    "REVOKER_ROLE",
                    "revoke-root",
                    args.state_root,
                )
            ],
        )
        return

    plan = load_plan(Path(args.plan), args.expected_plan_hash)
    backend = registry_backend()
    verify_plan_target(backend, plan)
    journal = (
        ReceiptJournal(
            Path(args.receipt_output),
            args.command,
            args.expected_plan_hash,
        )
        if args.receipt_output
        else None
    )
    on_receipt = journal.append if journal else None
    if args.command == "publish-root":
        receipts = publish_root(backend, plan, on_receipt)
    elif args.command == "publish-resolvers":
        receipts = publish_resolvers(backend, plan, on_receipt)
    elif args.command == "bind-endpoints":
        receipts = bind_endpoints(backend, plan, on_receipt)
    elif args.command == "unbind-endpoints":
        receipts = unbind_endpoints(backend, plan, on_receipt)
    elif args.command == "revoke-removed":
        receipts = revoke_removed_resolvers(backend, plan, on_receipt)
    all_receipts = journal.transactions if journal else receipts
    write_receipts_if_requested(
        args.receipt_output,
        args.command,
        all_receipts,
        args.expected_plan_hash,
    )


def sign_identities(input_path: Path, private_key_path: Path, output_path: Path) -> None:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    identities = payload.get("identities")
    if not isinstance(identities, list) or not identities:
        raise ValueError("unsigned artifact must contain a non-empty identities list")
    private_key = private_key_path.read_text(encoding="utf-8").strip()
    for identity in identities:
        identity.pop("signature", None)
        identity["endpoints"] = [
            ResolverEndpoint.from_dict(endpoint).to_dict()
            for endpoint in identity.get("endpoints", [])
        ]
        if identity.get("agent") is not None:
            identity["agent"]["algorithm"] = str(identity["agent"]["algorithm"]).lower()
        validate_identity_structure(identity)
        identity["signature"] = sign_object_ed25519(identity, private_key)
    write_json_atomic(output_path, {"identities": identities})


def build_norn_snapshot(
    plan: dict,
    *,
    chain_id: int,
    genesis_block_hash: str,
    registry_address: str,
    registry_key: str,
    snapshot_version: int,
    checkpoint_height: int,
    checkpoint_hash: str,
    valid_until: int,
    issuer: str,
    key_id: str,
) -> dict:
    published_at = int(time.time())
    snapshot = {
        "schema_version": NORN_REGISTRY_SNAPSHOT_V1,
        "chain_id": chain_id,
        "genesis_block_hash": normalize_fixed_hex(genesis_block_hash, 32),
        "registry_address": normalize_fixed_hex(registry_address, 20),
        "registry_key": registry_key,
        "registry_schema_hash": NORN_REGISTRY_SCHEMA_HASH_V1,
        "snapshot_version": snapshot_version,
        "checkpoint_height": checkpoint_height,
        "checkpoint_hash": normalize_fixed_hex(checkpoint_hash, 32),
        "state_root": normalize_fixed_hex(plan["state_root"], 32),
        "root_status": "ACTIVE",
        "published_at": published_at,
        "valid_until": valid_until,
        "issuer": issuer,
        "key_id": key_id,
        "entries": [
            {
                field: entry[field]
                for field in (
                    "server_id",
                    "resolver_id_key",
                    "object_hash",
                    "object_version",
                    "valid_until",
                    "status",
                    "endpoint_keys",
                )
            }
            for entry in sorted(plan["entries"], key=lambda item: item["server_id"])
        ],
    }
    validate_norn_snapshot_shape(snapshot)
    return snapshot


def validate_norn_snapshot_shape(snapshot: dict) -> None:
    if snapshot.get("schema_version") != NORN_REGISTRY_SNAPSHOT_V1:
        raise ValueError("Norn snapshot schema_version is invalid")
    if snapshot.get("registry_schema_hash") != NORN_REGISTRY_SCHEMA_HASH_V1:
        raise ValueError("Norn snapshot schema hash is invalid")
    if (
        int(snapshot.get("chain_id", 0)) <= 0
        or int(snapshot.get("snapshot_version", 0)) <= 0
        or int(snapshot.get("checkpoint_height", 0)) <= 0
        or int(snapshot.get("published_at", 0)) <= 0
        or int(snapshot.get("valid_until", 0)) <= int(snapshot.get("published_at", 0))
        or snapshot.get("root_status") != "ACTIVE"
        or not str(snapshot.get("registry_key", "")).strip()
        or not str(snapshot.get("issuer", "")).strip()
        or not str(snapshot.get("key_id", "")).strip()
        or not snapshot.get("entries")
    ):
        raise ValueError("Norn snapshot required fields are invalid")
    normalize_fixed_hex(snapshot["genesis_block_hash"], 32)
    normalize_fixed_hex(snapshot["registry_address"], 20)
    normalize_fixed_hex(snapshot["checkpoint_hash"], 32)
    normalize_fixed_hex(snapshot["state_root"], 32)
    server_ids = [entry["server_id"] for entry in snapshot["entries"]]
    if server_ids != sorted(set(server_ids)):
        raise ValueError("Norn snapshot entries must be sorted by unique server_id")


def build_external_snapshot(
    plan: dict,
    *,
    driver: str,
    chain_identity: str,
    registry_locator: str,
    registry_schema_hash: str,
    generation: int,
    checkpoint_height: int,
    checkpoint_hash: str,
    valid_until: int,
    issuer: str,
    key_id: str,
) -> dict:
    published_at = int(time.time())
    registry_schema_hash = normalize_fixed_hex(registry_schema_hash, 32)
    snapshot = {
        "schema_version": EXTERNAL_REGISTRY_SNAPSHOT_V1,
        "target": {
            "adapter": f"external-{driver}",
            "chain_identity": chain_identity,
            "registry_locator": registry_locator,
            "registry_schema_hash": registry_schema_hash,
        },
        "checkpoint": {
            "number": checkpoint_height,
            "hash": normalize_fixed_hex(checkpoint_hash, 32),
        },
        "generation": generation,
        "state_root": normalize_fixed_hex(plan["state_root"], 32),
        "root_status": "ACTIVE",
        "published_at": published_at,
        "valid_until": valid_until,
        "issuer": issuer,
        "key_id": key_id,
        "entries": [
            {
                field: entry[field]
                for field in (
                    "server_id",
                    "resolver_id_key",
                    "object_hash",
                    "object_version",
                    "valid_until",
                    "status",
                    "endpoint_keys",
                )
            }
            for entry in sorted(plan["entries"], key=lambda item: item["server_id"])
        ],
    }
    validate_external_snapshot_shape(snapshot)
    return snapshot


def validate_external_snapshot_shape(snapshot: dict) -> None:
    if snapshot.get("schema_version") != EXTERNAL_REGISTRY_SNAPSHOT_V1:
        raise ValueError("external snapshot schema_version is invalid")
    target = snapshot.get("target")
    checkpoint = snapshot.get("checkpoint")
    if not isinstance(target, dict) or not isinstance(checkpoint, dict):
        raise ValueError("external snapshot target or checkpoint is missing")
    adapter = str(target.get("adapter", ""))
    driver = adapter.removeprefix("external-") if adapter.startswith("external-") else ""
    if (
        not driver
        or len(driver) > 23
        or any(not (char.islower() or char.isdigit() or char == "-") for char in driver)
    ):
        raise ValueError("external snapshot adapter driver is invalid")
    expected_target = {
        "adapter": adapter,
        "chain_identity": str(target.get("chain_identity", "")),
        "registry_locator": str(target.get("registry_locator", "")),
        "registry_schema_hash": normalize_fixed_hex(
            target.get("registry_schema_hash", ""),
            32,
        ),
    }
    if (
        target != expected_target
        or not expected_target["chain_identity"].strip()
        or not expected_target["registry_locator"].strip()
        or expected_target["registry_schema_hash"] == "0x" + "00" * 32
        or int(snapshot.get("generation", 0)) <= 0
        or int(checkpoint.get("number", 0)) <= 0
        or int(snapshot.get("published_at", 0)) <= 0
        or int(snapshot.get("valid_until", 0)) <= int(snapshot.get("published_at", 0))
        or snapshot.get("root_status") != "ACTIVE"
        or not str(snapshot.get("issuer", "")).strip()
        or not str(snapshot.get("key_id", "")).strip()
        or not snapshot.get("entries")
    ):
        raise ValueError("external snapshot required fields are invalid")
    normalize_fixed_hex(checkpoint.get("hash", ""), 32)
    normalize_fixed_hex(snapshot.get("state_root", ""), 32)
    server_ids = [entry["server_id"] for entry in snapshot["entries"]]
    if server_ids != sorted(set(server_ids)):
        raise ValueError("external snapshot entries must be sorted by unique server_id")


def normalize_fixed_hex(value: str, size: int) -> str:
    normalized = str(value).lower()
    raw = normalized[2:] if normalized.startswith("0x") else ""
    if len(raw) != size * 2 or any(char not in "0123456789abcdef" for char in raw):
        raise ValueError(f"value must be 0x-prefixed {size}-byte hex")
    return "0x" + raw


def load_identities(identity_path: Path, issuer_path: Path) -> list[dict]:
    payload = json.loads(identity_path.read_text(encoding="utf-8"))
    identities = payload.get("identities")
    if not isinstance(identities, list) or not identities:
        raise ValueError("identity artifact must contain a non-empty identities list")
    issuers = IssuerKeyRegistry.from_file(issuer_path)
    server_ids: set[str] = set()
    endpoint_owners: dict[str, str] = {}
    for identity in identities:
        validate_identity(identity, issuers)
        server_id = identity["server_id"]
        if server_id in server_ids:
            raise ValueError(f"duplicate server_id: {server_id}")
        server_ids.add(server_id)
        for endpoint in identity["endpoints"]:
            endpoint_key = endpoint_lookup_key(ResolverEndpoint.from_dict(endpoint))
            previous = endpoint_owners.setdefault(endpoint_key, server_id)
            if previous != server_id:
                raise ValueError(
                    f"endpoint {endpoint_key} is shared by {previous} and {server_id}"
                )
    return identities


def validate_identity(identity: dict, issuers: IssuerKeyRegistry) -> None:
    validate_identity_structure(identity)
    if not verify_object_signature_with_registry(identity, issuers):
        raise ValueError(f"identity signature is invalid: {identity.get('server_id')}")


def validate_identity_structure(identity: dict) -> None:
    if identity.get("schema_version") != "dns-server-identity-v2":
        raise ValueError("unsupported identity schema")
    role = identity.get("role")
    if role not in {
        "RECURSIVE",
        "FORWARDER",
        "ROOT_AUTHORITY",
        "TLD_AUTHORITY",
        "AUTHORITATIVE",
    }:
        raise ValueError("identity role is invalid")
    if identity.get("status") != "ACTIVE":
        raise ValueError("only ACTIVE identities may be published")
    for field in ("server_id", "operator_id", "issuer", "key_id"):
        if not str(identity.get(field, "")).strip():
            raise ValueError(f"identity {field} is required")
    if int(identity.get("object_version", 0)) <= 0:
        raise ValueError("identity object_version must be positive")
    if int(identity.get("valid_until", 0)) <= int(identity.get("valid_from", 0)):
        raise ValueError("identity validity window is invalid")
    if not identity.get("endpoints"):
        raise ValueError("identity must contain at least one endpoint")
    if len(identity["endpoints"]) > 32:
        raise ValueError("identity must not contain more than 32 endpoints")
    if bool(identity.get("anycast")) != bool(identity.get("anycast_service_id")):
        raise ValueError("identity anycast fields are inconsistent")
    endpoint_keys = {
        endpoint_lookup_key(ResolverEndpoint.from_dict(endpoint))
        for endpoint in identity["endpoints"]
    }
    if len(endpoint_keys) != len(identity["endpoints"]):
        raise ValueError("identity contains duplicate endpoints")
    agent = identity.get("agent")
    if role in {"RECURSIVE", "FORWARDER"} and not agent:
        raise ValueError("recursive/forwarder identity must bind an Agent")
    if agent:
        if str(agent.get("algorithm", "")).lower() != "ed25519":
            raise ValueError("Agent binding must use Ed25519")
        try:
            public_key = base64.b64decode(agent["public_key"], validate=True)
        except (KeyError, ValueError, binascii.Error) as error:
            raise ValueError("Agent public key is invalid base64") from error
        if len(public_key) != 32:
            raise ValueError("Agent public key must contain 32 bytes")
        if not str(agent.get("key_id", "")).strip():
            raise ValueError("Agent key_id is required")
        if not str(agent.get("service_url", "")).startswith("https://"):
            raise ValueError("Agent service_url must use HTTPS")


def build_plan(
    identities: list[dict],
    root_version: int,
    chain_id: int,
    contract_address: str,
    contract_code_hash: str,
    previous_plan: dict | None = None,
) -> dict:
    if root_version <= 0:
        raise ValueError("root version must be positive")
    target = normalize_plan_target(chain_id, contract_address, contract_code_hash)
    if root_version > 1 and previous_plan is None:
        raise ValueError("root versions above 1 require the previous approved plan")
    if previous_plan is not None:
        if previous_plan["target"] != target:
            raise ValueError("previous plan targets a different Registry deployment")
        if int(previous_plan["root_version"]) >= root_version:
            raise ValueError("root version must increase from the previous plan")
    entries = []
    leaves = []
    for identity in sorted(identities, key=lambda item: item["server_id"]):
        resolver_key = resolver_id_key(identity["server_id"])
        identity_hash = object_hash(identity)
        leaf = merkle_leaf(
            resolver_key,
            identity_hash,
            int(identity["object_version"]),
            identity["status"],
        )
        leaves.append(leaf)
        entries.append(
            {
                "server_id": identity["server_id"],
                "resolver_id_key": resolver_key,
                "object_hash": identity_hash,
                "object_version": int(identity["object_version"]),
                "valid_until": int(identity["valid_until"]),
                "status": identity["status"],
                "endpoint_keys": [
                    endpoint_lookup_key(ResolverEndpoint.from_dict(endpoint))
                    for endpoint in identity["endpoints"]
                ],
                "leaf_hash": leaf,
            }
        )
    previous_entries = {
        entry["server_id"]: entry for entry in (previous_plan or {}).get("entries", [])
    }
    current_entries = {entry["server_id"]: entry for entry in entries}
    endpoint_unbinds = []
    resolver_revocations = []
    for server_id, previous in sorted(previous_entries.items()):
        current = current_entries.get(server_id)
        current_endpoints = set(current["endpoint_keys"]) if current else set()
        for endpoint_key in sorted(set(previous["endpoint_keys"]) - current_endpoints):
            endpoint_unbinds.append(
                {
                    "server_id": server_id,
                    "resolver_id_key": previous["resolver_id_key"],
                    "endpoint_key": endpoint_key,
                }
            )
        if current is None:
            resolver_revocations.append(
                {
                    "server_id": server_id,
                    "resolver_id_key": previous["resolver_id_key"],
                }
            )
    plan = {
        "schema_version": "registry-publication-plan-v2",
        "target": target,
        "previous_plan_hash": previous_plan["plan_hash"] if previous_plan else None,
        "root_version": root_version,
        "state_root": merkle_root(leaves),
        "entries": entries,
        "endpoint_unbinds": endpoint_unbinds,
        "resolver_revocations": resolver_revocations,
    }
    plan["plan_hash"] = object_hash(plan)
    return plan


def load_plan(path: Path, expected_hash: str) -> dict:
    plan = json.loads(path.read_text(encoding="utf-8"))
    embedded_hash = plan.pop("plan_hash", None)
    actual_hash = object_hash(plan)
    plan["plan_hash"] = embedded_hash
    if embedded_hash != actual_hash or actual_hash.lower() != expected_hash.lower():
        raise ValueError("publication plan hash does not match the independently approved hash")
    if plan.get("schema_version") != "registry-publication-plan-v2":
        raise ValueError("unsupported publication plan schema")
    target = plan.get("target")
    if not isinstance(target, dict):
        raise ValueError("publication plan target is missing")
    normalized_target = normalize_plan_target(
        target.get("chain_id"),
        target.get("contract_address"),
        target.get("contract_code_hash"),
    )
    if target != normalized_target:
        raise ValueError("publication plan target is not canonical")
    if not isinstance(plan.get("endpoint_unbinds"), list) or not isinstance(
        plan.get("resolver_revocations"), list
    ):
        raise ValueError("publication plan removal actions are missing")
    return plan


def load_previous_plan(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    embedded_hash = payload.get("plan_hash")
    if not isinstance(embedded_hash, str):
        raise ValueError("previous publication plan has no integrity hash")
    return load_plan(path, embedded_hash)


def normalize_plan_target(
    chain_id: int,
    contract_address: str,
    contract_code_hash: str,
) -> dict:
    try:
        chain_id = int(chain_id)
    except (TypeError, ValueError) as error:
        raise ValueError("plan chain_id must be a positive integer") from error
    address = str(contract_address).lower()
    code_hash = str(contract_code_hash).lower()
    if chain_id <= 0:
        raise ValueError("plan chain_id must be a positive integer")
    if (
        len(address) != 42
        or not address.startswith("0x")
        or not _nonzero_hex(address[2:], 40)
    ):
        raise ValueError("plan contract address must be a nonzero 20-byte hex value")
    if (
        len(code_hash) != 66
        or not code_hash.startswith("0x")
        or not _nonzero_hex(code_hash[2:], 64)
    ):
        raise ValueError("plan contract code hash must be a nonzero bytes32 hex value")
    return {
        "chain_id": chain_id,
        "contract_address": address,
        "contract_code_hash": code_hash,
    }


def _nonzero_hex(value: str, width: int) -> bool:
    try:
        return len(value) == width and int(value, 16) != 0
    except ValueError:
        return False


def verify_plan_target(backend: Web3RegistryBackend, plan: dict) -> None:
    expected = normalize_plan_target(
        backend.config.chain_id,
        backend.config.contract_address,
        backend.contract_code_hash,
    )
    if plan["target"] != expected:
        raise ValueError("publication plan target does not match the live Registry deployment")


def registry_backend() -> Web3RegistryBackend:
    settings = load_settings()
    settings.validate_for("registry-writer")
    return Web3RegistryBackend(
        Web3RegistryConfig(
            rpc_url=settings.web3_rpc_url,
            contract_address=settings.web3_contract_address,
            chain_id=settings.web3_chain_id,
            abi=load_contract_abi(Path(settings.web3_abi_path)),
            private_key_env=settings.web3_private_key_env or None,
            private_key_file=settings.web3_private_key_file or None,
            keystore_file=settings.web3_keystore_file or None,
            keystore_password_file=settings.web3_keystore_password_file or None,
            sender_address=settings.web3_sender_address or None,
            expected_code_hash=settings.web3_contract_code_hash,
            request_timeout_seconds=settings.web3_request_timeout_seconds,
            transaction_timeout_seconds=settings.web3_transaction_timeout_seconds,
        )
    )


def publish_root(
    backend: Web3RegistryBackend,
    plan: dict,
    on_receipt: Callable[[dict], None] | None = None,
) -> list[dict]:
    receipts = []
    record = backend.get_root_record(plan["state_root"])
    if record is not None and record.status == "REVOKED":
        raise ValueError("publication plan root has been permanently revoked")
    if record is not None and record.status == "ACTIVE":
        if record.version != int(plan["root_version"]):
            raise ValueError("active Root version conflicts with the approved plan")
        return receipts
    if record is None or record.status != "ACTIVE":
        receipt = backend.publish_root(
            plan["state_root"],
            version=int(plan["root_version"]),
        )
        if receipt is not None:
            record_receipt(
                receipts,
                transaction_evidence(
                    receipt,
                    "ROOT_PUBLISHER_ROLE",
                    "publish-root",
                    plan["state_root"],
                ),
                on_receipt,
            )
    return receipts


def publish_resolvers(
    backend: Web3RegistryBackend,
    plan: dict,
    on_receipt: Callable[[dict], None] | None = None,
) -> list[dict]:
    receipts = []
    if backend.get_root_status(plan["state_root"]) != "ACTIVE":
        raise ValueError("Root Publisher must activate the approved root first")
    for entry in plan["entries"]:
        current = backend.get_resolver_anchor(entry["resolver_id_key"])
        arguments = (
            entry["resolver_id_key"],
            entry["object_hash"],
            plan["state_root"],
            int(entry["object_version"]),
            int(entry["valid_until"]),
            entry["status"],
        )
        if current is None:
            receipt = backend.publish_resolver(*arguments)
            operation = "publish-resolver"
        elif current.object_version < int(entry["object_version"]):
            receipt = backend.update_resolver(*arguments)
            operation = "update-resolver"
        elif (
            current.object_version != int(entry["object_version"])
            or current.object_hash != entry["object_hash"]
            or current.state_root != plan["state_root"]
            or current.valid_until != int(entry["valid_until"])
            or current.status != entry["status"]
        ):
            raise ValueError(f"on-chain resolver conflicts with plan: {entry['server_id']}")
        else:
            receipt = None
            operation = ""
        if receipt is not None:
            record_receipt(
                receipts,
                transaction_evidence(
                    receipt,
                    "RESOLVER_PUBLISHER_ROLE",
                    operation,
                    entry["server_id"],
                ),
                on_receipt,
            )
    return receipts


def bind_endpoints(
    backend: Web3RegistryBackend,
    plan: dict,
    on_receipt: Callable[[dict], None] | None = None,
) -> list[dict]:
    receipts = []
    for entry in plan["entries"]:
        current = backend.get_resolver_anchor(entry["resolver_id_key"])
        if (
            current is None
            or current.object_hash != entry["object_hash"]
            or current.state_root != plan["state_root"]
            or current.status != "ACTIVE"
        ):
            raise ValueError(f"Resolver Publisher phase incomplete: {entry['server_id']}")
        for endpoint_key in entry["endpoint_keys"]:
            existing = backend.get_endpoint_binding(endpoint_key)
            if existing not in (None, entry["resolver_id_key"]):
                raise ValueError(f"endpoint conflict: {endpoint_key}")
            if existing is None:
                receipt = backend.bind_endpoint(endpoint_key, entry["resolver_id_key"])
                if receipt is not None:
                    record_receipt(
                        receipts,
                        transaction_evidence(
                            receipt,
                            "ENDPOINT_MANAGER_ROLE",
                            "bind-endpoint",
                            endpoint_key,
                        ),
                        on_receipt,
                    )
    return receipts


def unbind_endpoints(
    backend: Web3RegistryBackend,
    plan: dict,
    on_receipt: Callable[[dict], None] | None = None,
) -> list[dict]:
    receipts = []
    for removal in plan["endpoint_unbinds"]:
        existing = backend.get_endpoint_binding(removal["endpoint_key"])
        if existing is None:
            continue
        if existing != removal["resolver_id_key"]:
            raise ValueError(
                f"endpoint removal owner conflict: {removal['endpoint_key']}"
            )
        receipt = backend.unbind_endpoint(removal["endpoint_key"])
        if receipt is not None:
            record_receipt(
                receipts,
                transaction_evidence(
                    receipt,
                    "ENDPOINT_MANAGER_ROLE",
                    "unbind-endpoint",
                    removal["endpoint_key"],
                ),
                on_receipt,
            )
    return receipts


def revoke_removed_resolvers(
    backend: Web3RegistryBackend,
    plan: dict,
    on_receipt: Callable[[dict], None] | None = None,
) -> list[dict]:
    receipts = []
    for removal in plan["resolver_revocations"]:
        current = backend.get_resolver_anchor(removal["resolver_id_key"])
        if current is None:
            raise ValueError(f"removed resolver is absent on chain: {removal['server_id']}")
        if current.status != "REVOKED":
            receipt = backend.revoke_resolver(removal["resolver_id_key"])
            if receipt is not None:
                record_receipt(
                    receipts,
                    transaction_evidence(
                        receipt,
                        "REVOKER_ROLE",
                        "revoke-resolver",
                        removal["server_id"],
                    ),
                    on_receipt,
                )
    return receipts


def transaction_evidence(
    receipt: dict,
    role: str,
    operation: str,
    target_object: str,
) -> dict:
    required = ("transactionHash", "blockNumber", "blockHash", "status", "gasUsed")
    missing = [field for field in required if field not in receipt]
    if missing:
        raise ValueError(f"transaction receipt is missing fields: {', '.join(missing)}")
    return {
        "transaction_hash": receipt["transactionHash"],
        "sender": receipt.get("from", ""),
        "role": role,
        "block_number": int(receipt["blockNumber"]),
        "block_hash": receipt["blockHash"],
        "status": int(receipt["status"]),
        "gas_used": int(receipt["gasUsed"]),
        "operation": operation,
        "target_object": target_object,
    }


def record_receipt(
    receipts: list[dict],
    evidence: dict,
    on_receipt: Callable[[dict], None] | None,
) -> None:
    receipts.append(evidence)
    if on_receipt:
        on_receipt(evidence)


class ReceiptJournal:
    def __init__(self, path: Path, phase: str, context_hash: str):
        self.path = path
        self.phase = phase
        self.context_hash = context_hash.lower()
        self.transactions: list[dict] = []
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (
                payload.get("schema_version")
                != "registry-publication-receipts-v1"
                or payload.get("phase") != phase
                or str(payload.get("context_hash", "")).lower() != self.context_hash
                or not isinstance(payload.get("transactions"), list)
            ):
                raise ValueError("receipt journal does not match the requested phase and plan")
            self.transactions = payload["transactions"]

    def append(self, evidence: dict) -> None:
        tx_hash = evidence["transaction_hash"].lower()
        if all(
            item.get("transaction_hash", "").lower() != tx_hash
            for item in self.transactions
        ):
            self.transactions.append(evidence)
        self.write()

    def write(self) -> None:
        write_json_atomic(
            self.path,
            {
                "schema_version": "registry-publication-receipts-v1",
                "phase": self.phase,
                "context_hash": self.context_hash,
                "transactions": self.transactions,
            },
        )


def write_receipts_if_requested(
    output: str | None,
    phase: str,
    transactions: list[dict],
    context_hash: str | None = None,
) -> None:
    if output:
        write_json_atomic(
            Path(output),
            {
                "schema_version": "registry-publication-receipts-v1",
                "phase": phase,
                "context_hash": context_hash,
                "transactions": transactions,
            },
        )
    print(json.dumps({"phase": phase, "transaction_count": len(transactions)}))


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


if __name__ == "__main__":
    main()
