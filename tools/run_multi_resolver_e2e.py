from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from web3 import Web3

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import AdminPublisher, endpoint_lookup_key
from resolver_identity.chain.contract_loader import default_foundry_artifact
from resolver_identity.chain.web3_backend import Web3RegistryBackend, Web3RegistryConfig
from resolver_identity.crypto.signatures import generate_ed25519_keypair
from resolver_identity.db.repositories import IndexerRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.models.endpoint import ResolverEndpoint

SECRET = "multi-agent-secret"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "docker/state/resolver_identity.db"
WEB3_ENV_PATH = PROJECT_ROOT / "docker/state/web3.env"
AGENT_R1_ENV_PATH = PROJECT_ROOT / "docker/state/agent-r1.env"
AGENT_R2_ENV_PATH = PROJECT_ROOT / "docker/state/agent-r2.env"
FAILURE_DIR = PROJECT_ROOT / "docker/state/e2e-failures"
QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x04test\x00\x00\x01\x00\x01"
EXPECTED_A = b"\xcb\x00\x71\x0a"  # 203.0.113.10
R1_IP = "172.30.0.11"
R2_IP = "172.30.0.12"
ANVIL_ACCOUNT0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
HOST_RPC_URL = "http://127.0.0.1:18545"
CONTAINER_RPC_URL = "http://anvil:8545"
DYNAMIC_SERVICES = ("local-wrapper", "event-watcher", "indexer", "agent-r1", "agent-r2")
PYTHON_SERVICES = ("indexer", "agent-r2", "agent-r1", "event-watcher", "local-wrapper")
R1_AGENT_PRIVATE, R1_AGENT_PUBLIC = generate_ed25519_keypair()
R2_AGENT_PRIVATE, R2_AGENT_PUBLIC = generate_ed25519_keypair()
BAD_AGENT_PRIVATE, _BAD_AGENT_PUBLIC = generate_ed25519_keypair()


class ScenarioTimeout(RuntimeError):
    pass


class E2ERunner:
    def __init__(self, compose: list[str], compose_file: str, timeout_seconds: int):
        self.compose = compose
        self.compose_file = str((PROJECT_ROOT / compose_file).resolve()) if not Path(compose_file).is_absolute() else compose_file
        self.timeout_seconds = timeout_seconds
        self.backend: Web3RegistryBackend | None = None
        self.published: dict[str, dict[str, Any]] = {}

    def bootstrap(self) -> None:
        stage("build contract")
        forge = _which("forge")
        if not forge:
            raise RuntimeError("forge is required")
        subprocess.run([forge, "build"], cwd=PROJECT_ROOT / "contracts", check=True)

        stage("prepare state")
        _prepare_state_dir()

        stage("build Python service images once")
        self.compose_run("build", *PYTHON_SERVICES)

        stage("start stable infrastructure")
        self.compose_run("up", "-d", "anvil", "resolver-r1", "resolver-r2")
        wait_for_anvil()

    def setup_baseline(
        self,
        *,
        agent_resolver_id: str = "operator-a/r1",
        agent_private_key: str = R1_AGENT_PRIVATE,
    ) -> tuple[Web3RegistryBackend, dict[str, dict[str, Any]]]:
        stage("stop scenario-dependent services")
        self.compose_run("stop", *DYNAMIC_SERVICES, check=False)
        self.compose_run("rm", "-f", "-s", *DYNAMIC_SERVICES, check=False)

        stage("deploy fresh registry and seed R1/R2 identities")
        _reset_db()
        backend = deploy_registry(PROJECT_ROOT)
        write_web3_env(backend.config.contract_address)
        write_agent_r1_env(resolver_id=agent_resolver_id, private_key=agent_private_key)
        write_agent_r2_env(private_key=R2_AGENT_PRIVATE)
        published = seed_identities(backend, [("operator-a/r1", R1_IP), ("operator-a/r2", R2_IP)])

        stage("start scenario-dependent services without rebuilding")
        self.compose_run("up", "-d", *PYTHON_SERVICES)
        wait_for_services_healthy(self.compose, self.compose_file, PYTHON_SERVICES, timeout=90)
        wait_for_udp_dns("127.0.0.1", 1053, allow_servfail=True)
        self.backend = backend
        self.published = published
        return backend, published

    def restart(self, *services: str) -> None:
        stage(f"restart affected services: {', '.join(services)}")
        self.compose_run("stop", *services, check=False)
        self.compose_run("rm", "-f", "-s", *services, check=False)
        self.compose_run("up", "-d", *services)
        wait_for_services_healthy(self.compose, self.compose_file, services, timeout=60)

    def run_scenario(self, name: str, action: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        stage(f"scenario {name}: start")
        started = time.monotonic()
        try:
            with scenario_timeout(self.timeout_seconds, name):
                result = action()
        except Exception:
            archive = capture_failure(self.compose, self.compose_file, name)
            print(f"[e2e] scenario {name}: FAILED; diagnostics={archive}", file=sys.stderr, flush=True)
            raise
        elapsed = time.monotonic() - started
        result = {**result, "elapsed_seconds": round(elapsed, 3)}
        stage(f"scenario {name}: passed in {elapsed:.2f}s")
        return result

    def compose_run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([*self.compose, "-f", self.compose_file, *args], cwd=PROJECT_ROOT, check=check)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Docker Compose v1 Web3 multi-resolver Resolver Identity E2E")
    parser.add_argument("--compose-file", default="docker-compose.multi-resolver.yml")
    parser.add_argument("--scenario", choices=("basic", "revocation", "config-version", "all"), default="all")
    parser.add_argument("--scenario-timeout", type=int, default=120, help="maximum seconds for one named scenario")
    parser.add_argument("--no-down", action="store_true", help="leave Compose services running after completion")
    args = parser.parse_args()

    compose = _compose_cmd()
    if compose is None:
        print("docker-compose v1 is required", file=sys.stderr)
        raise SystemExit(1)

    os.chdir(PROJECT_ROOT)
    runner = E2ERunner(compose, args.compose_file, args.scenario_timeout)
    down_cmd = [*compose, "-f", runner.compose_file, "down", "-v", "--remove-orphans"]
    results: dict[str, Any] = {}
    failed = False
    try:
        runner.bootstrap()
        if args.scenario in {"basic", "all"}:
            results["basic"] = run_basic_group(runner)
        if args.scenario in {"revocation", "all"}:
            results["revocation"] = run_revocation_group(runner)
        if args.scenario in {"config-version", "all"}:
            results["config-version"] = run_config_version_group(runner)
        print(json.dumps({"docker_multi_resolver_web3_e2e": "ok", "scenario": args.scenario, "results": results}, ensure_ascii=False, indent=2))
    except Exception:
        failed = True
        raise
    finally:
        if not args.no_down:
            stage("final cleanup")
            subprocess.run(down_cmd, cwd=PROJECT_ROOT, check=False)
            if not failed:
                _prepare_state_dir()
        elif failed:
            print("[e2e] failure scene left running because --no-down was set", file=sys.stderr, flush=True)


def run_basic_group(runner: E2ERunner) -> dict[str, Any]:
    runner.setup_baseline()
    results: dict[str, Any] = {}
    results["positive"] = runner.run_scenario("basic.positive", scenario_positive)
    results["r1_missing"] = runner.run_scenario("basic.r1-missing", lambda: scenario_hidden_identity(runner, "operator-a/r1", R1_IP, restart_wrapper=True))
    results["r2_missing"] = runner.run_scenario("basic.r2-missing", lambda: scenario_hidden_identity(runner, "operator-a/r2", R2_IP))
    results["agent_wrong_resolver_id"] = runner.run_scenario("basic.agent-wrong-id", lambda: scenario_agent_wrong_id(runner))
    results["agent_unavailable"] = runner.run_scenario("basic.agent-unavailable", lambda: scenario_agent_unavailable(runner))
    results["agent_bad_signature"] = runner.run_scenario("basic.agent-bad-signature", lambda: scenario_agent_bad_signature(runner))
    results["positive_after_restores"] = runner.run_scenario("basic.positive-after-restores", scenario_positive)
    return results


def run_revocation_group(runner: E2ERunner) -> dict[str, Any]:
    results: dict[str, Any] = {}
    backend, published = runner.setup_baseline()
    results["r2_chain_revoke"] = runner.run_scenario("revocation.r2", lambda: scenario_r2_revoke(backend, published))
    backend, published = runner.setup_baseline()
    results["root_revoke"] = runner.run_scenario("revocation.root", lambda: scenario_root_revoke(backend, published))
    return results


def run_config_version_group(runner: E2ERunner) -> dict[str, Any]:
    runner.setup_baseline()
    return {"config_version_change": runner.run_scenario("config-version.change", lambda: scenario_config_change(runner))}


def scenario_positive() -> dict[str, Any]:
    udp = query_udp(QUERY, "127.0.0.1", 1053)
    tcp = query_tcp(QUERY, "127.0.0.1", 1053)
    hot = query_udp(QUERY, "127.0.0.1", 1053)
    assert_noerror_answer(udp)
    assert_noerror_answer(tcp)
    assert_noerror_answer(hot)
    return {"udp_noerror": True, "tcp_noerror": True, "hot_cache_noerror": True}


def scenario_hidden_identity(runner: E2ERunner, resolver_id: str, ip: str, *, restart_wrapper: bool = False) -> dict[str, Any]:
    set_identity_visible(resolver_id, ip, visible=False)
    if restart_wrapper:
        runner.restart("local-wrapper")
    try:
        response = query_udp(QUERY, "127.0.0.1", 1053)
        assert_servfail_no_original_answer(response)
    finally:
        set_identity_visible(resolver_id, ip, visible=True)
        if restart_wrapper:
            runner.restart("local-wrapper")
    return {"servfail": True, "temporarily_hidden": resolver_id}


def scenario_agent_wrong_id(runner: E2ERunner) -> dict[str, Any]:
    write_agent_r1_env(resolver_id="operator-a/not-r1")
    runner.restart("agent-r1")
    try:
        assert_servfail_no_original_answer(query_udp(QUERY, "127.0.0.1", 1053))
    finally:
        write_agent_r1_env()
        runner.restart("agent-r1")
    return {"servfail": True}


def scenario_agent_unavailable(runner: E2ERunner) -> dict[str, Any]:
    runner.compose_run("stop", "agent-r1")
    try:
        assert_servfail_no_original_answer(query_udp(QUERY, "127.0.0.1", 1053))
    finally:
        runner.compose_run("up", "-d", "agent-r1")
        wait_for_services_healthy(runner.compose, runner.compose_file, ("agent-r1",), timeout=60)
    return {"servfail": True}


def scenario_agent_bad_signature(runner: E2ERunner) -> dict[str, Any]:
    write_agent_r1_env(private_key=BAD_AGENT_PRIVATE)
    runner.restart("agent-r1")
    try:
        assert_servfail_no_original_answer(query_udp(QUERY, "127.0.0.1", 1053))
    finally:
        write_agent_r1_env()
        runner.restart("agent-r1")
    return {"servfail": True}


def scenario_r2_revoke(backend: Web3RegistryBackend, published: dict[str, dict[str, Any]]) -> dict[str, Any]:
    assert_noerror_answer(query_udp(QUERY, "127.0.0.1", 1053))
    backend.revoke_resolver(published["operator-a/r2"]["resolver_id_key"])
    wait_for_servfail()
    return {"servfail_after_revoke": True}


def scenario_root_revoke(backend: Web3RegistryBackend, published: dict[str, dict[str, Any]]) -> dict[str, Any]:
    assert_noerror_answer(query_udp(QUERY, "127.0.0.1", 1053))
    backend.revoke_root(published["operator-a/r2"]["state_root"])
    wait_for_servfail()
    return {"servfail_after_root_revoke": True}


def scenario_config_change(runner: E2ERunner) -> dict[str, Any]:
    assert_noerror_answer(query_udp(QUERY, "127.0.0.1", 1053))
    write_agent_r1_env(config_version="2")
    runner.restart("agent-r1")
    transient_servfails = wait_for_noerror_after_fail_closed_transition()
    return {
        "query_after_config_change": True,
        "old_chain_context_invalidated_by_wrapper": True,
        "transient_servfails": transient_servfails,
    }


def set_identity_visible(resolver_id: str, ip: str, *, visible: bool) -> None:
    endpoint = ResolverEndpoint(ip=ip, port=1053, transport="udp")
    lookup_key = endpoint_lookup_key(endpoint)
    conn = connect(DB_PATH)
    try:
        if visible:
            row = conn.execute("SELECT resolver_id_key FROM resolver_objects WHERE resolver_id=?", (resolver_id,)).fetchone()
            if not row:
                raise RuntimeError(f"cannot restore missing resolver object: {resolver_id}")
            conn.execute(
                "INSERT OR REPLACE INTO resolver_lookup_index(lookup_key,resolver_id_key,resolver_id) VALUES(?,?,?)",
                (lookup_key, row["resolver_id_key"], resolver_id),
            )
        else:
            conn.execute("DELETE FROM resolver_lookup_index WHERE lookup_key=?", (lookup_key,))
        conn.execute("DELETE FROM trusted_cache WHERE resolver_id=?", (resolver_id,))
        conn.commit()
    finally:
        conn.close()


def deploy_registry(project_root: Path) -> Web3RegistryBackend:
    artifact_path = default_foundry_artifact(project_root)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    abi = artifact["abi"]
    bytecode = artifact["bytecode"]["object"] if isinstance(artifact.get("bytecode"), dict) else artifact["bytecode"]
    web3 = Web3(Web3.HTTPProvider(HOST_RPC_URL))
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    account = web3.to_checksum_address(ANVIL_ACCOUNT0)
    tx_hash = contract.constructor(account).transact({"from": account})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    if int(receipt.get("status", 0)) != 1:
        raise RuntimeError("contract deployment failed")
    return Web3RegistryBackend(Web3RegistryConfig(HOST_RPC_URL, receipt["contractAddress"], int(web3.eth.chain_id), abi, sender_address=account))


def seed_identities(backend: Web3RegistryBackend, resolvers: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    conn = connect(DB_PATH)
    init_db(conn)
    publisher = AdminPublisher(IndexerRepository(conn), backend, SECRET)
    out: dict[str, dict[str, Any]] = {}
    try:
        for resolver_id, ip in resolvers:
            agent_public_key = R1_AGENT_PUBLIC if resolver_id == "operator-a/r1" else R2_AGENT_PUBLIC if resolver_id == "operator-a/r2" else None
            obj = build_resolver_object(
                resolver_id,
                "operator-a",
                "Operator A",
                [{"endpoint_id": "udp-1053", "ip": ip, "port": 1053, "transport": "udp"}],
                "2026-07-01T00:00:00Z",
                "2027-07-01T00:00:00Z",
                agent_public_key_b64=agent_public_key,
            )
            out[resolver_id] = publisher.publish(obj)
    finally:
        conn.close()
    return out


def write_web3_env(contract_address: str) -> None:
    WEB3_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEB3_ENV_PATH.write_text(
        "\n".join(
            [
                "RESOLVER_IDENTITY_REGISTRY_MODE=web3",
                f"RESOLVER_IDENTITY_WEB3_RPC_URL={CONTAINER_RPC_URL}",
                f"RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS={contract_address}",
                "RESOLVER_IDENTITY_WEB3_CHAIN_ID=31337",
                "RESOLVER_IDENTITY_WEB3_ABI_PATH=/app/contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json",
                f"RESOLVER_IDENTITY_WEB3_SENDER_ADDRESS={ANVIL_ACCOUNT0}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_agent_r1_env(
    resolver_id: str = "operator-a/r1",
    private_key: str = R1_AGENT_PRIVATE,
    upstream_ip: str = R2_IP,
    config_version: str = "1",
) -> None:
    AGENT_R1_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    AGENT_R1_ENV_PATH.write_text(
        "\n".join(
            [
                f"RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64={private_key}",
                f"RESOLVER_IDENTITY_AGENT_RESOLVER_ID={resolver_id}",
                f"RESOLVER_IDENTITY_AGENT_ENDPOINT_IP={R1_IP}",
                "RESOLVER_IDENTITY_AGENT_ENDPOINT_PORT=1053",
                "RESOLVER_IDENTITY_AGENT_ENDPOINT_TRANSPORT=udp",
                f"RESOLVER_IDENTITY_UPSTREAM_IP={upstream_ip}",
                "RESOLVER_IDENTITY_UPSTREAM_PORT=1053",
                "RESOLVER_IDENTITY_UPSTREAM_TRANSPORT=udp",
                f"RESOLVER_IDENTITY_AGENT_CONFIG_VERSION={config_version}",
                "RESOLVER_IDENTITY_AGENT_UPSTREAM_AGENT_BASE_URLS=172.30.0.12:1053:udp=http://agent-r2:8010",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_agent_r2_env(private_key: str = R2_AGENT_PRIVATE, config_version: str = "1") -> None:
    AGENT_R2_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    AGENT_R2_ENV_PATH.write_text(
        "\n".join(
            [
                f"RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64={private_key}",
                f"RESOLVER_IDENTITY_AGENT_CONFIG_VERSION={config_version}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _reset_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = connect(DB_PATH)
    init_db(conn)
    conn.close()


def _prepare_state_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    write_web3_env("0x0000000000000000000000000000000000000000")
    write_agent_r1_env()
    write_agent_r2_env()


def query_udp(query: bytes, host: str, port: int, timeout: float = 3.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(4096)
        return data


def query_tcp(query: bytes, host: str, port: int, timeout: float = 3.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(len(query).to_bytes(2, "big") + query)
        size = int.from_bytes(_recv_exact(sock, 2), "big")
        return _recv_exact(sock, size)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("TCP DNS connection closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def wait_for_udp_dns(host: str, port: int, allow_servfail: bool = False) -> None:
    deadline = time.time() + 90
    last_exc = None
    while time.time() < deadline:
        try:
            response = query_udp(QUERY, host, port, timeout=2)
            if len(response) >= 4 and (allow_servfail or rcode(response) == 0):
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(1)
    raise RuntimeError(f"Docker DNS wrapper did not become ready: {last_exc}")


def wait_for_servfail() -> None:
    deadline = time.time() + 25
    last_rcode = None
    while time.time() < deadline:
        response = query_udp(QUERY, "127.0.0.1", 1053)
        last_rcode = rcode(response)
        if last_rcode == 2 and EXPECTED_A not in response:
            return
        time.sleep(1)
    raise AssertionError(f"expected SERVFAIL before deadline, last rcode={last_rcode}")


def wait_for_noerror_after_fail_closed_transition() -> int:
    deadline = time.time() + 25
    transient_servfails = 0
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = query_udp(QUERY, "127.0.0.1", 1053)
            if rcode(response) == 0:
                assert_noerror_answer(response)
                return transient_servfails
            assert_servfail_no_original_answer(response)
            transient_servfails += 1
        except (OSError, TimeoutError) as exc:
            last_error = exc
        time.sleep(0.5)
    raise AssertionError(f"expected NOERROR recovery before deadline; last transport error={last_error}")


def wait_for_anvil() -> None:
    web3 = Web3(Web3.HTTPProvider(HOST_RPC_URL))
    deadline = time.time() + 90
    last_exc = None
    while time.time() < deadline:
        try:
            _ = web3.eth.chain_id
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(1)
    raise RuntimeError(f"Anvil did not become ready: {last_exc}")


def wait_for_services_healthy(compose: list[str], compose_file: str, services: tuple[str, ...], timeout: int) -> None:
    deadline = time.time() + timeout
    pending = set(services)
    while pending and time.time() < deadline:
        for service in list(pending):
            result = subprocess.run([*compose, "-f", compose_file, "ps", "-q", service], cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
            container_id = result.stdout.strip()
            if not container_id:
                continue
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", container_id],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if state in {"healthy", "running"}:
                pending.remove(service)
            elif state in {"unhealthy", "exited", "dead"}:
                raise RuntimeError(f"service {service} entered terminal state {state}")
        if pending:
            time.sleep(1)
    if pending:
        raise RuntimeError(f"services did not become healthy before timeout: {sorted(pending)}")


def assert_noerror_answer(response: bytes) -> None:
    assert rcode(response) == 0, f"expected NOERROR, got rcode={rcode(response)}"
    assert EXPECTED_A in response, "expected example.test A 203.0.113.10 in DNS response"


def assert_servfail_no_original_answer(response: bytes) -> None:
    assert rcode(response) == 2, f"expected SERVFAIL, got rcode={rcode(response)}"
    assert EXPECTED_A not in response, "SERVFAIL leaked original DNS answer"


def rcode(response: bytes) -> int:
    return -1 if len(response) < 4 else response[3] & 0x0F


@contextmanager
def scenario_timeout(seconds: int, name: str):
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def handle_timeout(_signum, _frame):
        raise ScenarioTimeout(f"scenario {name} exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def capture_failure(compose: list[str], compose_file: str, scenario: str) -> Path:
    FAILURE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = scenario.replace("/", "-").replace(".", "-")
    path = FAILURE_DIR / f"{int(time.time())}-{safe_name}.log"
    with path.open("w", encoding="utf-8") as output:
        output.write(f"scenario={scenario}\n")
        for args in (("ps",), ("logs", "--tail", "240", "local-wrapper", "agent-r1", "agent-r2", "event-watcher", "indexer")):
            output.write(f"\n$ {' '.join([*compose, '-f', compose_file, *args])}\n")
            subprocess.run([*compose, "-f", compose_file, *args], cwd=PROJECT_ROOT, stdout=output, stderr=subprocess.STDOUT, text=True, check=False)
    return path


def stage(message: str) -> None:
    print(f"[e2e {time.strftime('%H:%M:%S')}] {message}", flush=True)


def _compose_cmd() -> list[str] | None:
    executable = shutil.which("docker-compose")
    if not executable:
        return None
    try:
        subprocess.run([executable, "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    return [executable]


def _which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    foundry = Path.home() / ".foundry/bin" / name
    return str(foundry) if foundry.exists() else None


if __name__ == "__main__":
    main()
