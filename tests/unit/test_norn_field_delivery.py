from __future__ import annotations

import copy
import importlib.util
import json
import os
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "manage_norn_field_delivery",
    REPO_ROOT / "tools" / "manage_norn_field_delivery.py",
)
assert SPEC and SPEC.loader
field = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(field)

ACCEPTANCE_SPEC = importlib.util.spec_from_file_location(
    "run_norn_field_acceptance",
    REPO_ROOT / "tools" / "run_norn_field_acceptance.py",
)
assert ACCEPTANCE_SPEC and ACCEPTANCE_SPEC.loader
acceptance = importlib.util.module_from_spec(ACCEPTANCE_SPEC)
ACCEPTANCE_SPEC.loader.exec_module(acceptance)


def _inventory(tmp_path: Path, version: str = "0.3.0-test") -> dict:
    inventory = field.load_inventory(REPO_ROOT / "deploy" / "field" / "inventory.example.yaml")
    inventory["release"]["version"] = version
    inventory["release"]["git_commit"] = subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    inventory["release"]["images"] = {
        key: f"registry.internal/{key}@sha256:{index:064x}"
        for index, key in enumerate(field.IMAGE_KEYS, start=1)
    }
    inventory["norn"]["genesis_hash"] = "0x" + "a" * 64
    inventory["management"]["data_dir"] = str(tmp_path / "management-data")
    inventory["management"]["work_dir"] = str(tmp_path / "management-work")
    inventory["management"]["secret_dir"] = str(tmp_path / "management-secrets")
    inventory["management"]["norn_tls_dir"] = str(tmp_path / "management-norn-tls")
    for index, node in enumerate(inventory["norn"]["nodes"]):
        node["data_dir"] = str(tmp_path / f"norn-data-{index}")
        node["config_dir"] = str(tmp_path / f"norn-config-{index}")
        node["tls_dir"] = str(tmp_path / f"norn-tls-{index}")
    for index, resolver in enumerate(inventory["resolvers"]):
        resolver["data_dir"] = str(tmp_path / f"resolver-data-{index}")
        resolver["trace_socket"] = str(tmp_path / f"trace-{index}")
        resolver["secret_dir"] = str(tmp_path / f"resolver-secrets-{index}")
        resolver["agent_tls_dir"] = str(tmp_path / f"resolver-agent-tls-{index}")
        resolver["norn_tls_dir"] = str(tmp_path / f"resolver-norn-tls-{index}")
        resolver["existing_resolver_config"] = str(
            tmp_path / f"existing-resolver-{index}" / "kresd.conf"
        )
    return inventory


def _extract_package(release: Path, kind: str, destination: Path) -> Path:
    archive = next(release.glob(f"resolver-identity-{kind}-*.tar.gz"))
    with tarfile.open(archive, "r:gz") as handle:
        handle.extractall(destination, filter="data")
    roots = list(destination.iterdir())
    assert len(roots) == 1
    return roots[0]


def _lifecycle_env(install_root: Path) -> dict[str, str]:
    bin_dir = install_root.parent / "test-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "# Lifecycle simulation validates invocation; CI validates real Compose.\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    return {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RI_INSTALL_ROOT": str(install_root),
        "RI_FIELD_SIMULATION": "true",
        "RI_FIELD_MIN_FREE_MB": "1",
    }


def test_example_is_valid_restricted_yaml_template():
    inventory = field.load_inventory(REPO_ROOT / "deploy" / "field" / "inventory.example.yaml")
    field.validate_inventory(inventory, template=True)
    with pytest.raises(field.DeliveryError, match="placeholder"):
        field.validate_inventory(inventory)


def test_peer_id_parser_ignores_bootstrap_errors_and_keeps_full_multihash():
    peer_id = "QmXTgjTK8n9yiNWY2LmRqiJMphKZB9X8jgWD2PuRK11sAh"
    logs = (
        f'level=info msg="Node address: /ip4/127.0.0.1/tcp/31258/p2p/{peer_id}"\n'
        'level=error msg="bootstrap /p2p/QmWrongAddress"\n'
    )
    assert acceptance.Lab._peer_id_from_logs(logs) == peer_id


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["norn"]["nodes"][1].update(
                data_dir=value["norn"]["nodes"][0]["data_dir"]
            ),
            "Norn data_dir",
        ),
        (
            lambda value: value["norn"]["nodes"][1].update(
                node_key_profile=value["norn"]["nodes"][0]["node_key_profile"]
            ),
            "node_key_profile",
        ),
        (
            lambda value: value["resolvers"][1].update(
                data_dir=value["resolvers"][0]["data_dir"]
            ),
            "resolver data_dir",
        ),
        (
            lambda value: value["resolvers"][1].update(
                wrapper_upstreams=["udp://10.70.30.10:53"]
            ),
            "must not configure Wrapper",
        ),
        (
            lambda value: value["resolvers"][0].update(
                wrapper_upstreams=["udp://10.70.30.11:53"]
            ),
            "only the local Knot TCP endpoint",
        ),
        (
            lambda value: value["release"]["images"].update(
                rust="registry.internal/rust:latest"
            ),
            "sha256",
        ),
    ],
)
def test_inventory_rejects_shared_or_unsafe_configuration(tmp_path, mutation, message):
    inventory = _inventory(tmp_path)
    mutation(inventory)
    with pytest.raises(field.DeliveryError, match=message):
        field.validate_inventory(inventory)


def test_rendered_release_contains_three_complete_secret_free_packages(tmp_path):
    inventory = _inventory(tmp_path)
    release = field.render(inventory, tmp_path / "artifacts")
    manifest = field.verify_release(release)

    assert manifest["production_trace_ready"] is False
    assert manifest["simulated_server_count"] == 6
    assert {item["kind"] for item in manifest["packages"]} == set(field.PACKAGE_KINDS)
    assert set(manifest["images"]) == set(field.IMAGE_KEYS)
    subprocess.run(
        ["sha256sum", "--check", "--strict", "SHA256SUMS"],
        cwd=release,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    required = {
        "preflight.sh",
        "install.sh",
        "health-check.sh",
        "upgrade.sh",
        "rollback.sh",
        "uninstall.sh",
        "docker-compose.yml",
        ".env.example",
        "common/lifecycle.sh",
        "PACKAGE-MANIFEST.json",
        "PACKAGE-SHA256SUMS",
    }
    for kind in field.PACKAGE_KINDS:
        extracted = _extract_package(release, kind, tmp_path / f"extract-{kind}")
        names = {
            path.relative_to(extracted).as_posix()
            for path in extracted.rglob("*")
            if path.is_file()
        }
        assert required <= names
        if kind == "management":
            assert "nornctl.sh" in names
        field._scan_package(extracted)
        subprocess.run(
            ["sha256sum", "--check", "--strict", "PACKAGE-SHA256SUMS"],
            cwd=extracted,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def test_release_trace_readiness_requires_script_generated_acceptance(tmp_path):
    inventory = _inventory(tmp_path)
    evidence = {
        "schema_version": field.TRACE_ACCEPTANCE_SCHEMA,
        "source_commit": inventory["release"]["git_commit"],
        "release_version": field.RELEASE_VERSION,
        "resolver_name": field.TRACE_RESOLVER_NAME,
        "resolver_version": field.TRACE_RESOLVER_VERSION,
        "resolver_upstream_commit": field.TRACE_RESOLVER_COMMIT,
        "production_trace_ready": True,
        "generated_by": "tools/run_production_trace_acceptance.py",
        "secret_scan_clean": True,
        "cross_talk_count": 0,
        "concurrency": 128,
        "time_window_matching": False,
        "failure_closed": True,
        "sqlite_integrity": "ok",
        "temporary_environment_cleaned": True,
        "results": {key: "passed" for key in field.TRACE_REQUIRED_RESULTS},
    }
    acceptance_file = tmp_path / "acceptance.json"
    acceptance_file.write_text(json.dumps(evidence), encoding="utf-8")
    release = field.render(
        inventory,
        tmp_path / "qualified",
        trace_acceptance=acceptance_file,
    )
    assert field.verify_release(release)["production_trace_ready"] is True
    manifest = field.verify_release(release)
    assert manifest["field_package_ready"] is True
    assert manifest["real_server_deployed"] is False
    assert manifest["production_traffic_enabled"] is False

    evidence["cross_talk_count"] = 1
    acceptance_file.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(field.DeliveryError, match="cross-talk"):
        field.render(
            inventory,
            tmp_path / "rejected",
            trace_acceptance=acceptance_file,
        )

    secret_requirements = json.loads(
        (release / "secret-requirements.json").read_text(encoding="utf-8")
    )
    assert len(secret_requirements["hosts"]) == 6
    assert all(
        requirement["generated_by_renderer"] is False
        for requirement in secret_requirements["hosts"].values()
    )

    resolver_env = (
        release / "hosts" / "resolver-L01-r1" / "config" / ".env"
    ).read_text(encoding="utf-8")
    assert "RI_TRACE_WAIT_MILLIS='5000'" in resolver_env
    assert "RI_WRAPPER_AGENT_TIMEOUT_MS='7500'" in resolver_env
    assert "RI_WRAPPER_MAX_CONCURRENT_VERIFICATIONS='32'" in resolver_env


def test_adapter_access_and_role_boundaries_are_encoded_in_compose():
    compose = (
        REPO_ROOT / "deploy" / "field" / "resolver-link" / "docker-compose.yml"
    ).read_text(encoding="utf-8")
    registry = compose.split("  registry-sync:", 1)[1].split("  agent:", 1)[0]
    resolver = compose.split("  resolver:", 1)[1].split("  trace-producer:", 1)[0]
    producer = compose.split("  trace-producer:", 1)[1].split("  registry-sync:", 1)[0]
    agent = compose.split("  agent:", 1)[1].split("  trace-adapter:", 1)[0]
    wrapper = compose.split("  wrapper:", 1)[1].split("networks:", 1)[0]

    assert "RI_CHAIN_RPC_URLS" in registry
    assert "RI_NORN_GENESIS_BLOCK_HASH" in registry
    assert "RI_KNOT_TRACE_HOOK_SOCKET" in resolver
    assert "RI_TRACE_SOCKET:" not in resolver
    assert "RI_TRACE_SOCKET=" not in resolver
    assert "network_mode: none" in producer
    assert "RI_KNOT_TRACE_EXPECTED_UID" in producer
    assert "ri-knot-trace-producer" in producer
    assert '"${RI_MANAGEMENT_BIND_ADDRESS:?required}:8443:8443/tcp"' in agent
    assert '"${RI_MANAGEMENT_BIND_ADDRESS:?required}:9108:9108/tcp"' in wrapper
    assert '"${RI_RESOLVER_BIND_ADDRESS:?required}:53:1053/udp"' in resolver
    assert "/var/cache/knot-resolver" in resolver
    for section in (agent, wrapper):
        assert "RI_CHAIN_RPC" not in section
        assert "RI_NORN_" not in section
    assert "profiles: [first-hop]" in wrapper

    proxy = (
        REPO_ROOT / "deploy" / "field" / "norn-node" / "nginx-readonly.conf"
    ).read_text(encoding="utf-8")
    assert "ReadContractAddress" in proxy
    assert "GetBlockByNumber" in proxy
    assert "GetBlockNumber" in proxy
    assert "SendTransactionWithData" not in proxy
    assert "return 403" in proxy
    assert "@@NORN_NODE_HOSTNAME@@" in proxy
    for path in ("fastcgi_temp", "uwsgi_temp", "scgi_temp"):
        assert f"/tmp/{path}" in proxy

    node_compose = (
        REPO_ROOT / "deploy" / "field" / "norn-node" / "docker-compose.yml"
    ).read_text(encoding="utf-8")
    assert "RI_NORN_NODE_HOSTNAME:" in node_compose
    assert "start-read-proxy.sh" in node_compose

    node_start = (
        REPO_ROOT / "deploy" / "field" / "norn-node" / "start-norn.sh"
    ).read_text(encoding="utf-8")
    assert 'if [[ "${RI_NORN_ROLE:?}" == "node-a" ]]' in node_start
    assert "arguments+=(-g)" in node_start
    assert 'elif [[ "${RI_NORN_ROLE}" == "node-b" ]]' in node_start


@pytest.mark.parametrize(
    ("kind", "host"),
    [
        ("management", "ri-hub-mgmt-01"),
        ("norn-node", "norn-node-a"),
        ("resolver-link", "resolver-L01-r1"),
    ],
)
def test_install_is_idempotent_for_each_package_kind(tmp_path, kind, host):
    inventory = _inventory(tmp_path)
    release = field.render(inventory, tmp_path / "artifacts")
    package = _extract_package(release, kind, tmp_path / f"extract-{kind}")
    config = release / "hosts" / host / "config"
    install_root = tmp_path / "new-server" / kind / "opt" / "resolver-identity"
    environment = _lifecycle_env(install_root)

    command = [
        str(package / "install.sh"),
        "--version",
        inventory["release"]["version"],
        "--config-dir",
        str(config),
    ]
    subprocess.run(command, env=environment, check=True)
    first_target = (install_root / "current").resolve()
    subprocess.run(command, env=environment, check=True)
    assert (install_root / "current").resolve() == first_target


def test_upgrade_failure_rolls_back_and_uninstall_preserves_data(tmp_path):
    version_one = _inventory(tmp_path, "0.3.0-test-1")
    release_one = field.render(version_one, tmp_path / "artifacts-one")
    version_two = copy.deepcopy(version_one)
    version_two["release"]["version"] = "0.3.0-test-2"
    release_two = field.render(version_two, tmp_path / "artifacts-two")
    version_three = copy.deepcopy(version_one)
    version_three["release"]["version"] = "0.3.0-test-3"
    release_three = field.render(version_three, tmp_path / "artifacts-three")

    packages = [
        _extract_package(release, "management", tmp_path / f"extract-{index}")
        for index, release in enumerate((release_one, release_two, release_three), 1)
    ]
    configs = [
        release / "hosts" / "ri-hub-mgmt-01" / "config"
        for release in (release_one, release_two, release_three)
    ]
    install_root = tmp_path / "install"
    environment = _lifecycle_env(install_root)
    data_dir = Path(version_one["management"]["data_dir"])

    subprocess.run(
        [str(packages[0] / "install.sh"), "--config-dir", str(configs[0])],
        env=environment,
        check=True,
    )
    marker = data_dir / "retained.txt"
    marker.write_text("retain", encoding="utf-8")
    subprocess.run(
        [str(packages[1] / "upgrade.sh"), "--config-dir", str(configs[1])],
        env=environment,
        check=True,
    )
    assert (install_root / "current").resolve().name == "0.3.0-test-2"

    failed_environment = {**environment, "RI_FIELD_FORCE_HEALTH_FAILURE": "true"}
    result = subprocess.run(
        [str(packages[2] / "upgrade.sh"), "--config-dir", str(configs[2])],
        env=failed_environment,
        check=False,
    )
    assert result.returncode != 0
    assert (install_root / "current").resolve().name == "0.3.0-test-2"
    assert marker.read_text(encoding="utf-8") == "retain"

    subprocess.run(
        [str(packages[1] / "rollback.sh")], env=environment, check=True
    )
    assert (install_root / "current").resolve().name == "0.3.0-test-1"
    subprocess.run(
        [str(packages[0] / "uninstall.sh")], env=environment, check=True
    )
    assert marker.is_file()
    assert not (install_root / "current").exists()

    subprocess.run(
        [str(packages[0] / "install.sh"), "--config-dir", str(configs[0])],
        env=environment,
        check=True,
    )
    subprocess.run(
        [str(packages[0] / "uninstall.sh"), "--purge-data"],
        env=environment,
        check=True,
    )
    assert not data_dir.exists()


def test_resolver_lifecycle_backs_up_and_preserves_existing_configuration(tmp_path):
    inventory = _inventory(tmp_path, "0.3.0-trace-backup")
    existing = Path(inventory["resolvers"][0]["existing_resolver_config"])
    existing.parent.mkdir(parents=True)
    existing.write_text("-- original resolver configuration\n", encoding="utf-8")
    release = field.render(inventory, tmp_path / "artifacts")
    package = _extract_package(release, "resolver-link", tmp_path / "extract-resolver")
    config = release / "hosts" / "resolver-L01-r1" / "config"
    install_root = tmp_path / "install-resolver"
    environment = _lifecycle_env(install_root)

    subprocess.run(
        [str(package / "install.sh"), "--config-dir", str(config)],
        env=environment,
        check=True,
    )
    backup = install_root / "state" / "resolver-config" / "original.conf"
    assert backup.read_text(encoding="utf-8") == existing.read_text(encoding="utf-8")

    subprocess.run([str(package / "uninstall.sh")], env=environment, check=True)
    assert existing.read_text(encoding="utf-8") == "-- original resolver configuration\n"
    assert backup.is_file()
    trace_dir = Path(inventory["resolvers"][0]["trace_socket"])
    assert trace_dir.is_dir()
    assert stat.S_IMODE(trace_dir.stat().st_mode) == 0o2770


def test_modified_generated_resolver_configuration_fails_before_activation(tmp_path):
    inventory = _inventory(tmp_path, "0.3.0-trace-invalid-config")
    existing = Path(inventory["resolvers"][0]["existing_resolver_config"])
    existing.parent.mkdir(parents=True)
    existing.write_text("-- original resolver configuration\n", encoding="utf-8")
    release = field.render(inventory, tmp_path / "artifacts")
    package = _extract_package(release, "resolver-link", tmp_path / "extract-resolver")
    config = release / "hosts" / "resolver-L01-r1" / "config"
    (config / "kresd.conf").write_text("error('unapproved')\n", encoding="utf-8")
    install_root = tmp_path / "install-resolver"

    result = subprocess.run(
        [str(package / "install.sh"), "--config-dir", str(config)],
        env=_lifecycle_env(install_root),
        check=False,
    )
    assert result.returncode != 0
    assert not (install_root / "current").exists()
    assert existing.read_text(encoding="utf-8") == "-- original resolver configuration\n"


def test_resolver_install_rejects_agent_timeout_below_trace_wait(tmp_path):
    inventory = _inventory(tmp_path, "0.3.0-trace-timeout-order")
    release = field.render(inventory, tmp_path / "artifacts")
    package = _extract_package(release, "resolver-link", tmp_path / "extract-resolver")
    config = release / "hosts" / "resolver-L01-r1" / "config"
    with (config / ".env").open("a", encoding="utf-8") as handle:
        handle.write("RI_WRAPPER_AGENT_TIMEOUT_MS=4999\n")

    result = subprocess.run(
        [str(package / "install.sh"), "--config-dir", str(config)],
        env=_lifecycle_env(tmp_path / "install-resolver"),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "timeout must exceed" in result.stderr


def test_offline_image_archives_are_optional_and_checksummed(tmp_path):
    inventory = _inventory(tmp_path)
    archives = tmp_path / "images"
    archives.mkdir()
    for key in field.IMAGE_KEYS:
        (archives / f"{key}.tar").write_bytes(f"offline-{key}".encode())
    release = field.render(
        inventory,
        tmp_path / "artifacts",
        offline_image_dir=archives,
    )
    manifest = field.verify_release(release)
    assert manifest["delivery_modes"]["offline_archives_included"] is True
    archive_manifest = json.loads(
        (release / "offline-images" / "image-archives.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(archive_manifest["archives"]) == len(field.IMAGE_KEYS)
