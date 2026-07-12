from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.chain.contract_loader import default_foundry_artifact
from resolver_identity.chain.event_watcher import EventWatcher, WatcherState
from resolver_identity.chain.web3_backend import Web3RegistryBackend, Web3RegistryConfig
from resolver_identity.db.repositories import AuditLogRepository, IndexerRepository, TrustedCacheRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier
from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import UpstreamResolver

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
DNS_RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
ANVIL_ACCOUNT0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


async def forward_ok(query: bytes, host: str, port: int) -> bytes:
    return DNS_RESPONSE


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local Anvil Web3 registry end-to-end test")
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--port", type=int, default=0, help="Anvil port; 0 chooses a temporary free port")
    args = parser.parse_args()

    try:
        from web3 import Web3
    except ModuleNotFoundError as exc:
        print("web3 optional dependency is required: install with `python3 -m pip install -e '.[web3]'`", file=sys.stderr)
        raise SystemExit(1) from exc

    project_root = Path(args.project_root)
    contracts = project_root / "contracts"
    anvil = _which("anvil")
    forge = _which("forge")
    if not anvil or not forge:
        print("anvil/forge not available; install Foundry to run this integration", file=sys.stderr)
        raise SystemExit(1)

    subprocess.run([forge, "build"], cwd=contracts, check=True, capture_output=True, text=True)
    artifact_path = default_foundry_artifact(project_root)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    abi = artifact["abi"]
    bytecode = artifact["bytecode"]["object"] if isinstance(artifact.get("bytecode"), dict) else artifact["bytecode"]

    port = args.port or _free_tcp_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil_proc = subprocess.Popen([anvil, "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_rpc(Web3, rpc_url)
        web3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = int(web3.eth.chain_id)
        contract_address = deploy_contract(web3, abi, bytecode)
        backend = Web3RegistryBackend(Web3RegistryConfig(rpc_url, contract_address, chain_id, abi, sender_address=web3.to_checksum_address(ANVIL_ACCOUNT0)))
        assert_roles_configured(backend.contract, web3.to_checksum_address(ANVIL_ACCOUNT0))

        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "resolver_identity.db")
            init_db(conn)
            indexer = IndexerRepository(conn)
            cache_repo = TrustedCacheRepository(conn)
            cache = CacheManager(cache_repo)
            verifier = ResolverVerifier(indexer, backend, cache, VerificationPolicy.default(), "anvil-secret")
            publisher = AdminPublisher(indexer, backend, "anvil-secret")
            audit = AuditLogRepository(conn)
            coordinator = QueryCoordinator(verifier, audit=audit)
            watcher = EventWatcher(cache, audit=audit, confirmations=0, state=WatcherState(last_processed_block=0))

            first = publish_identity(publisher, "operator-a/resolver-01", "192.0.2.53")
            publish_events = watcher.poll_web3_events(web3, backend.contract)
            anchor = backend.get_resolver_anchor(first["resolver_id_key"])
            assert anchor and anchor.object_hash == first["object_hash"], "Web3 anchor read failed"
            assert backend.get_root_status(first["state_root"]) == "ACTIVE", "Web3 root status read failed"

            cold = verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
            assert cold.accepted and cold.evidence.get("cache") == "miss", cold.to_dict()
            hot = verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
            assert hot.accepted and hot.evidence.get("cache") == "hit", hot.to_dict()
            allowed = asyncio.run(coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok))
            assert allowed.accepted and allowed.response == DNS_RESPONSE, "DNS response was not released"

            backend.revoke_resolver(first["resolver_id_key"])
            resolver_revoke_events = watcher.poll_web3_events(web3, backend.contract)
            revoked_cache_row = cache_repo.list()[0]
            assert revoked_cache_row["status"] == "REVOKED", revoked_cache_row
            revoked = asyncio.run(coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.53")], forward_ok))
            assert not revoked.accepted and (revoked.response[3] & 0x0F) == 2, "resolver revoke did not fail closed"

            second = publish_identity(publisher, "operator-a/resolver-02", "192.0.2.54")
            second_cold = verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
            assert second_cold.accepted, second_cold.to_dict()
            backend.revoke_root(second["state_root"])
            root_revoke_events = watcher.poll_web3_events(web3, backend.contract)
            root_revoked_row = cache_repo.get_by_endpoint_lookup_key(second["endpoint_key"])
            assert root_revoked_row and root_revoked_row["status"] == "REVOKED", root_revoked_row
            root_revoked = asyncio.run(coordinator.coordinate(QUERY, [UpstreamResolver("192.0.2.54")], forward_ok))
            assert not root_revoked.accepted and (root_revoked.response[3] & 0x0F) == 2, "root revoke did not fail closed"

            third = publish_identity(publisher, "operator-a/resolver-03", "192.0.2.55")
            third_cold = verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp"))
            assert third_cold.accepted, third_cold.to_dict()
            # Simulate watcher downtime/missed ResolverUpdated event: do not poll logs;
            # reconcile by comparing trusted cache evidence with chain state.
            backend.update_resolver(third["resolver_id_key"], third["replacement_object_hash"], third["state_root"], 2, int(time.time()) + 3600, "ACTIVE")
            refresh = watcher.reconcile_registry_state(backend)
            assert refresh["expired"] >= 1, "poll refresh did not expire stale cache after missed event"

            failing_verifier = ResolverVerifier(indexer, FailingRegistryBackend(), CacheManager(TrustedCacheRepository(conn)), VerificationPolicy.default(), "anvil-secret")
            rpc_failure_result = failing_verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp"))
            assert not rpc_failure_result.accepted and rpc_failure_result.reasons == ["out_of_band_unavailable"], rpc_failure_result.to_dict()

            print(json.dumps({
                "anvil": "ok",
                "rpc_url": _redact_rpc_url(rpc_url),
                "contract": contract_address,
                "roles_configured": True,
                "publish_events": publish_events["events"],
                "anchor_read": True,
                "root_read": True,
                "cold_verified": cold.accepted,
                "hot_cache": hot.evidence.get("cache"),
                "dns_released": allowed.accepted,
                "resolver_revoke_events": resolver_revoke_events["events"],
                "resolver_cache_status_after_event": revoked_cache_row["status"],
                "resolver_revoke_servfail": not revoked.accepted,
                "root_revoke_events": root_revoke_events["events"],
                "root_cache_status_after_event": root_revoked_row["status"],
                "root_revoke_servfail": not root_revoked.accepted,
                "missed_event_poll_refresh_expired": refresh["expired"],
                "rpc_failure_fail_closed": not rpc_failure_result.accepted,
                "last_processed_block": watcher.state.last_processed_block,
                "audit_events": len(audit.list(100)),
            }, ensure_ascii=False, indent=2))
    finally:
        anvil_proc.terminate()
        try:
            anvil_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil_proc.kill()
            anvil_proc.wait(timeout=5)


def publish_identity(publisher: AdminPublisher, resolver_id: str, ip: str) -> dict[str, Any]:
    obj = build_resolver_object(
        resolver_id,
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    published = publisher.publish(obj)
    replacement = build_resolver_object(
        resolver_id,
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
        object_version=2,
    )
    # The integration only needs a different object hash to prove polling repair;
    # it does not publish this replacement object into the indexer.
    from resolver_identity.crypto.hashes import object_hash

    replacement.signature = obj.signature
    published["replacement_object_hash"] = object_hash(replacement.to_dict(include_signature=True))
    published["endpoint_key"] = published_endpoint_key(ip)
    return published


def published_endpoint_key(ip: str) -> str:
    from resolver_identity.admin.publisher import endpoint_lookup_key

    return endpoint_lookup_key(ResolverEndpoint(ip=ip, port=53, transport="udp"))


def wait_for_rpc(Web3, rpc_url: str) -> None:
    web3 = Web3(Web3.HTTPProvider(rpc_url))
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            _ = web3.eth.chain_id
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("local Anvil RPC did not become ready")


def deploy_contract(web3, abi: list, bytecode: str) -> str:
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = contract.constructor(web3.to_checksum_address(ANVIL_ACCOUNT0)).transact({"from": web3.to_checksum_address(ANVIL_ACCOUNT0)})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    if int(receipt.get("status", 0)) != 1:
        raise RuntimeError("contract deployment failed")
    return receipt["contractAddress"]


def assert_roles_configured(contract, account: str) -> None:
    roles = (
        contract.functions.DEFAULT_ADMIN_ROLE().call(),
        contract.functions.ROOT_PUBLISHER_ROLE().call(),
        contract.functions.RESOLVER_PUBLISHER_ROLE().call(),
        contract.functions.REVOKER_ROLE().call(),
        contract.functions.ENDPOINT_MANAGER_ROLE().call(),
    )
    for role in roles:
        assert contract.functions.hasRole(role, account).call(), "initial admin is missing a required role"


class FailingRegistryBackend:
    def get_endpoint_binding(self, endpoint_key: str) -> str | None:
        raise RuntimeError("temporary RPC failure")

    lookup_resolver_by_endpoint = get_endpoint_binding

    def get_anchor(self, resolver_id_key: str):
        raise RuntimeError("temporary RPC failure")

    get_resolver_anchor = get_anchor

    def get_root_status(self, state_root: str) -> str | None:
        raise RuntimeError("temporary RPC failure")


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _redact_rpc_url(rpc_url: str) -> str:
    return rpc_url.rsplit(":", 1)[0] + ":<local-anvil-port>"


def _which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    foundry = Path.home() / ".foundry/bin" / name
    return str(foundry) if foundry.exists() else None


if __name__ == "__main__":
    main()
