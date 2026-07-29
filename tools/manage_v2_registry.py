from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare and apply DNS identity V2 Registry plans")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--input", required=True)
    sign.add_argument("--private-key-file", required=True)
    sign.add_argument("--output", required=True)

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

    revoke_resolver = subparsers.add_parser("revoke-resolver")
    revoke_resolver.add_argument("--server-id", required=True)
    revoke_root = subparsers.add_parser("revoke-root")
    revoke_root.add_argument("--state-root", required=True)

    args = parser.parse_args()
    if args.command == "sign":
        sign_identities(Path(args.input), Path(args.private_key_file), Path(args.output))
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
        Path(args.output).write_text(
            json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"plan_hash": plan["plan_hash"], "state_root": plan["state_root"]}))
        return

    if args.command == "revoke-resolver":
        backend = registry_backend()
        backend.revoke_resolver(resolver_id_key(args.server_id))
        return
    if args.command == "revoke-root":
        backend = registry_backend()
        backend.revoke_root(args.state_root)
        return

    plan = load_plan(Path(args.plan), args.expected_plan_hash)
    backend = registry_backend()
    verify_plan_target(backend, plan)
    if args.command == "publish-root":
        publish_root(backend, plan)
    elif args.command == "publish-resolvers":
        publish_resolvers(backend, plan)
    elif args.command == "bind-endpoints":
        bind_endpoints(backend, plan)
    elif args.command == "unbind-endpoints":
        unbind_endpoints(backend, plan)
    elif args.command == "revoke-removed":
        revoke_removed_resolvers(backend, plan)


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
    output_path.write_text(
        json.dumps({"identities": identities}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


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
            expected_code_hash=settings.web3_contract_code_hash,
            request_timeout_seconds=settings.web3_request_timeout_seconds,
            transaction_timeout_seconds=settings.web3_transaction_timeout_seconds,
        )
    )


def publish_root(backend: Web3RegistryBackend, plan: dict) -> None:
    record = backend.get_root_record(plan["state_root"])
    if record is not None and record.status == "REVOKED":
        raise ValueError("publication plan root has been permanently revoked")
    if record is not None and record.status == "ACTIVE":
        if record.version != int(plan["root_version"]):
            raise ValueError("active Root version conflicts with the approved plan")
        return
    if record is None or record.status != "ACTIVE":
        backend.publish_root(plan["state_root"], version=int(plan["root_version"]))


def publish_resolvers(backend: Web3RegistryBackend, plan: dict) -> None:
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
            backend.publish_resolver(*arguments)
        elif current.object_version < int(entry["object_version"]):
            backend.update_resolver(*arguments)
        elif (
            current.object_version != int(entry["object_version"])
            or current.object_hash != entry["object_hash"]
            or current.state_root != plan["state_root"]
            or current.valid_until != int(entry["valid_until"])
            or current.status != entry["status"]
        ):
            raise ValueError(f"on-chain resolver conflicts with plan: {entry['server_id']}")


def bind_endpoints(backend: Web3RegistryBackend, plan: dict) -> None:
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
                backend.bind_endpoint(endpoint_key, entry["resolver_id_key"])


def unbind_endpoints(backend: Web3RegistryBackend, plan: dict) -> None:
    for removal in plan["endpoint_unbinds"]:
        existing = backend.get_endpoint_binding(removal["endpoint_key"])
        if existing is None:
            continue
        if existing != removal["resolver_id_key"]:
            raise ValueError(
                f"endpoint removal owner conflict: {removal['endpoint_key']}"
            )
        backend.unbind_endpoint(removal["endpoint_key"])


def revoke_removed_resolvers(backend: Web3RegistryBackend, plan: dict) -> None:
    for removal in plan["resolver_revocations"]:
        current = backend.get_resolver_anchor(removal["resolver_id_key"])
        if current is None:
            raise ValueError(f"removed resolver is absent on chain: {removal['server_id']}")
        if current.status != "REVOKED":
            backend.revoke_resolver(removal["resolver_id_key"])


if __name__ == "__main__":
    main()
