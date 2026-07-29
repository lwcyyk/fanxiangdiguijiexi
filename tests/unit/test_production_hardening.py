import asyncio
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.routes_admin import build_admin_router
from resolver_identity.agent.identity import AgentIdentity
from resolver_identity.common.config import Settings
from resolver_identity.common.agent_transport import validate_agent_url_config
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.common.health import probe_database, probe_registry
from resolver_identity.common.http_security import MaxRequestBodySizeMiddleware
from resolver_identity.db.repositories import RuntimeStateRepository
from resolver_identity.db.schema import SCHEMA_VERSION, init_db
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.wrapper.routes_verify import build_verify_router
from resolver_identity.wrapper.resolver_chain import AgentResolverChainProvider, ChainDiscoveryError, ResolverChainContext, endpoint_cache_key
from resolver_identity.wrapper.metrics import RuntimeMetrics
from resolver_identity.wrapper.monitoring import start_monitoring_server
from tools.db_admin import backup_database, check_watcher, database_status


def test_production_wrapper_rejects_missing_strict_security_settings(monkeypatch):
    monkeypatch.setenv("RESOLVER_IDENTITY_ENVIRONMENT", "production")
    monkeypatch.setenv("RESOLVER_IDENTITY_REGISTRY_MODE", "sqlite")
    with pytest.raises(ValueError, match="production requires.*web3"):
        Settings().validate_for("wrapper")


def test_environment_name_does_not_silently_disable_production_checks():
    with pytest.raises(ValueError, match="must be production"):
        Settings(environment="prod").validate_for("wrapper")


def test_registry_writer_does_not_require_admin_or_issuer_private_keys():
    settings = Settings(
        environment="production",
        registry_mode="web3",
        web3_rpc_url="https://rpc.example",
        web3_contract_address="0x" + "11" * 20,
        web3_contract_code_hash="0x" + "22" * 32,
        web3_private_key_file="/secure/root-publisher.key",
        allow_hmac_object_signatures=False,
        issuer_keys_file="/secure/issuer-keys.json",
        admin_api_token="",
        issuer_private_key_b64="",
    )
    settings.validate_for("registry-writer")

    settings.web3_rpc_url = "http://rpc.example"
    with pytest.raises(ValueError, match="must use HTTPS"):
        settings.validate_for("registry-writer")


def test_endpoint_binding_key_includes_port_and_transport():
    udp53 = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    tcp53 = ResolverEndpoint(ip="192.0.2.53", port=53, transport="tcp")
    udp5353 = ResolverEndpoint(ip="192.0.2.53", port=5353, transport="udp")
    assert len({endpoint_lookup_key(udp53), endpoint_lookup_key(tcp53), endpoint_lookup_key(udp5353)}) == 3


def test_admin_router_requires_token():
    registry = SimpleNamespace(publish_root=lambda *args: None)
    indexer = SimpleNamespace(publish_root=lambda *args: None)
    publisher = SimpleNamespace(registry=registry, indexer=indexer)
    app = FastAPI()
    app.include_router(build_admin_router(publisher, admin_token="a" * 32))
    client = TestClient(app)
    payload = {"state_root": "0x" + "11" * 32}
    assert client.post("/v1/admin/roots/publish", json=payload).status_code == 401
    assert client.post("/v1/admin/roots/publish", json=payload, headers={"X-Admin-Token": "a" * 32}).status_code == 200


def test_http_body_limit_rejects_before_route_execution():
    app = FastAPI()
    app.add_middleware(MaxRequestBodySizeMiddleware, max_bytes=16)

    @app.post("/echo")
    def echo(payload: dict):
        return payload

    response = TestClient(app).post("/echo", content=b"x" * 17, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert TestClient(app).post("/echo", json={"ok": 1}).json() == {"ok": 1}


def test_empty_verification_query_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    app = FastAPI()
    app.include_router(build_verify_router(stack.verifier))
    response = TestClient(app).post("/v1/verify/query", json={"observed_resolvers": []})
    assert response.status_code == 200
    assert response.json() == {"accepted": False, "reason": "no_observed_resolvers", "results": []}


def test_query_audit_can_be_disabled():
    stack = create_prototype_stack(signature_secret="secret", query_audit_enabled=False)
    assert stack.coordinator.audit is None


def test_agent_http_url_requires_explicit_host_allowlist():
    with pytest.raises(ValueError, match="plaintext Agent URL host"):
        validate_agent_url_config("192.0.2.53=http://agent.example:8010", {"localhost"})
    validate_agent_url_config("192.0.2.53=http://agent-r1:8010", {"agent-r1"})


def test_database_schema_backup_and_watcher_health(tmp_path):
    database = tmp_path / "runtime.db"
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    RuntimeStateRepository(conn).set("watcher:last_success_epoch", f"{time.time():.6f}")
    conn.close()

    backup = tmp_path / "backups" / "runtime.db"
    result = backup_database(database, backup, force=False)
    assert result["integrity"] == "ok"
    assert len(result["sha256"]) == 64
    assert os.stat(backup).st_mode & 0o777 == 0o600
    assert database_status(backup)["schema_version"] == SCHEMA_VERSION
    assert check_watcher(database, max_age_seconds=5)["ok"] is True


def test_database_rejects_newer_schema():
    conn = sqlite3.connect(":memory:")
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    with pytest.raises(RuntimeError, match="newer than supported"):
        init_db(conn)


def test_deep_health_probes_database_and_registry_drift():
    stack = create_prototype_stack(signature_secret="secret")
    assert probe_database(stack.conn) == {"ok": True, "schema_version": SCHEMA_VERSION}
    assert probe_registry(stack.registry) == {"ok": True, "mode": "sqlite"}

    code_hash = "0x" + "ab" * 32

    class HashResult:
        def hex(self):
            return code_hash

    class FakeWeb3Type:
        @staticmethod
        def keccak(code):
            assert code == b"contract"
            return HashResult()

    eth = SimpleNamespace(chain_id=31337, block_number=42, get_code=lambda address: b"contract")
    registry = SimpleNamespace(
        web3=SimpleNamespace(eth=eth),
        config=SimpleNamespace(chain_id=31337, contract_address="0x" + "11" * 20),
        Web3=FakeWeb3Type,
        contract_code_hash=code_hash,
    )
    assert probe_registry(registry)["latest_block"] == 42
    eth.chain_id = 1
    with pytest.raises(RuntimeError, match="chain ID changed"):
        probe_registry(registry)
    eth.chain_id = 31337
    registry.contract_code_hash = "0x" + "cd" * 32
    with pytest.raises(RuntimeError, match="code hash changed"):
        probe_registry(registry)


async def test_monitoring_readiness_failure_returns_503():
    def unavailable():
        raise RuntimeError("database unavailable")

    server = await start_monitoring_server("127.0.0.1", 0, RuntimeMetrics(), readiness_check=unavailable)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        assert b"503 Service Unavailable" in await reader.read()
    finally:
        server.close()
        await server.wait_closed()


def test_agent_config_high_water_persists_across_provider_restart():
    stack = create_prototype_stack(signature_secret="secret")
    state = RuntimeStateRepository(stack.conn)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    key = endpoint_cache_key(endpoint)

    def context(version: str) -> ResolverChainContext:
        identity = AgentIdentity("operator-a/r1", endpoint, [], version)
        return ResolverChainContext(endpoint, identity, [endpoint], f"operator-a/r1:{version}")

    first = AgentResolverChainProvider({}, state_repository=state)
    first._update_context(key, context("2"))
    restarted = AgentResolverChainProvider({}, state_repository=state)
    with pytest.raises(ChainDiscoveryError, match="rollback"):
        restarted._update_context(key, context("1"))


@pytest.mark.parametrize("path,expected", [("/healthz", b"200 OK"), ("/readyz", b"200 OK"), ("/metrics", b"resolver_identity_up 1"), ("/missing", b"404 Not Found")])
async def test_monitoring_server_endpoints(path, expected):
    metrics = RuntimeMetrics()
    metrics.record_decision("ALLOW", 12.5, [])
    server = await start_monitoring_server("127.0.0.1", 0, metrics)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        await writer.drain()
        response = await reader.read()
        assert expected in response
    finally:
        server.close()
        await server.wait_closed()


def resolver_object(version=1, port=53):
    return build_resolver_object(
        "operator-a/production-r1",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": port, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
        object_version=version,
    )


def test_publisher_retry_repairs_indexer_after_chain_commit(monkeypatch):
    stack = create_prototype_stack(signature_secret="secret")
    obj = resolver_object()
    original_upsert = stack.indexer.upsert_resolver_object
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated crash after chain commit")
        return original_upsert(*args, **kwargs)

    monkeypatch.setattr(stack.indexer, "upsert_resolver_object", fail_once)
    with pytest.raises(RuntimeError, match="simulated crash"):
        stack.publisher.publish(obj)

    retried = stack.publisher.publish(obj)
    assert retried["idempotent"] is True
    assert stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")).accepted


def test_publisher_update_removes_old_endpoint_binding_and_lookup():
    stack = create_prototype_stack(signature_secret="secret")
    first = resolver_object(version=1, port=53)
    stack.publisher.publish(first)
    old_endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    old_key = endpoint_lookup_key(old_endpoint)

    stack.publisher.publish(resolver_object(version=2, port=5353))

    assert stack.registry.get_endpoint_binding(old_key) is None
    assert stack.indexer.lookup(old_key) is None
    assert not stack.verifier.verify_endpoint(old_endpoint).accepted
