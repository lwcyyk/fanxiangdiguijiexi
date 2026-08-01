#!/usr/bin/env python3
"""Validate and render non-secret Go-Norn field delivery packages."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIELD_ROOT = REPO_ROOT / "deploy" / "field"
PACKAGE_KINDS = ("management", "norn-node", "resolver-link")
IMAGE_KEYS = ("management", "rust", "knot", "norn", "nginx")
TRACE_ACCEPTANCE_SCHEMA = "resolver-identity-production-trace-acceptance-v1"
TRACE_RESOLVER_NAME = "Knot Resolver"
TRACE_RESOLVER_VERSION = "6.3.0"
TRACE_RESOLVER_COMMIT = "124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e"
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{1,127}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$")
IMAGE_RE = re.compile(r"^[^@\s]+@sha256:([0-9a-f]{64})$")
SECRET_KEY_RE = re.compile(
    r"(private.?key(?:_value)?|mnemonic|password|token_value|secret_value|api.?key)",
    re.IGNORECASE,
)
SECRET_CONTENT_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"(?:gh[pousr]_[A-Za-z0-9]{30,})|"
    rb"(?:AKIA|ASIA)[A-Z0-9]{16}"
)
LATEST_IMAGE_RE = re.compile(
    rb"(?:image:\s*|[A-Z_]+_IMAGE=)[^\r\n]*:latest(?:[\s'\"#]|$)",
    re.IGNORECASE,
)
FORBIDDEN_SUFFIXES = (
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keystore",
    ".jks",
)
TRACE_BLOCKER = (
    "P0: no script-generated all-passed Knot Resolver 6.3.0 production Trace acceptance "
    "evidence was supplied for this exact source commit"
)
TRACE_REQUIRED_RESULTS = {
    "real_resolver",
    "udp_query",
    "tcp_query",
    "same_qname_concurrency",
    "transaction_id_reuse",
    "cache_hit",
    "cname_resolution",
    "udp_to_tcp_fallback",
    "udp_timeout_retry",
    "multi_upstream_failover",
    "strict_context_binding",
    "modified_trace_rejected",
    "agent_unavailable_fail_closed",
    "stale_registry_fail_closed",
    "invalid_identity_fail_closed",
    "orphan_cache_trace_fail_closed",
    "trace_queue_full_fail_closed",
    "producer_crash_fail_closed",
    "resolver_restart",
    "resolver_link_install",
    "resolver_link_upgrade",
    "resolver_link_rollback",
    "fail_closed",
    "sqlite_integrity",
}


class DeliveryError(ValueError):
    """Raised when a field inventory or package violates delivery policy."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryError(f"duplicate inventory key: {key}")
        result[key] = value
    return result


def load_inventory(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except (OSError, json.JSONDecodeError) as error:
        raise DeliveryError(
            "inventory must use the repository's JSON-compatible YAML subset: " f"{error}"
        ) from error
    if not isinstance(value, dict):
        raise DeliveryError("inventory root must be an object")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeliveryError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise DeliveryError(f"{label} must be an array")
    return value


def _string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeliveryError(f"{label} must be a non-empty string")
    result = value.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise DeliveryError(f"{label} contains control characters")
    if pattern is not None and not pattern.fullmatch(result):
        raise DeliveryError(f"{label} has an invalid format")
    return result


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DeliveryError(f"{label} must be from {minimum} to {maximum}")
    return value


def _ip(value: Any, label: str) -> str:
    result = _string(value, label)
    try:
        address = ipaddress.ip_address(result)
    except ValueError as error:
        raise DeliveryError(f"{label} is not an IP address") from error
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise DeliveryError(f"{label} must be a routable field address")
    return result


def _absolute(value: Any, label: str) -> str:
    result = _string(value, label)
    path = Path(result)
    if not path.is_absolute() or ".." in path.parts:
        raise DeliveryError(f"{label} must be an absolute normalized path")
    return result


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise DeliveryError(f"{label} values must be unique")


def _reject_secret_fields(value: Any, path: str = "inventory") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_KEY_RE.search(key):
                raise DeliveryError(f"{path}.{key} must not contain a secret field")
            _reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{path}[{index}]")


def validate_inventory(data: dict[str, Any], *, template: bool = False) -> dict[str, Any]:
    _reject_secret_fields(data)
    if data.get("schema_version") != 1:
        raise DeliveryError("schema_version must be 1")

    release = _mapping(data.get("release"), "release")
    _string(release.get("version"), "release.version", VERSION_RE)
    commit = _string(release.get("git_commit"), "release.git_commit", COMMIT_RE)
    images = _mapping(release.get("images"), "release.images")
    if set(images) != set(IMAGE_KEYS):
        raise DeliveryError(f"release.images must contain exactly {', '.join(IMAGE_KEYS)}")
    for key in IMAGE_KEYS:
        image = _string(images[key], f"release.images.{key}")
        match = IMAGE_RE.fullmatch(image)
        if match is None:
            raise DeliveryError(f"release.images.{key} must use a complete sha256 digest")
        if ":latest" in image:
            raise DeliveryError("latest images are prohibited")
        if not template and match.group(1) == "0" * 64:
            raise DeliveryError(f"release.images.{key} is still a placeholder")
    if not template and commit == "0" * 40:
        raise DeliveryError("release.git_commit is still a placeholder")

    management = _mapping(data.get("management"), "management")
    management_host = _string(management.get("host"), "management.host", HOST_RE)
    _ip(management.get("management_ip"), "management.management_ip")
    _absolute(management.get("data_dir"), "management.data_dir")
    _absolute(management.get("work_dir"), "management.work_dir")
    _absolute(management.get("secret_dir"), "management.secret_dir")
    _absolute(management.get("norn_tls_dir"), "management.norn_tls_dir")

    norn = _mapping(data.get("norn"), "norn")
    _integer(norn.get("chain_id"), "norn.chain_id", 1, 2**63 - 1)
    genesis = _string(norn.get("genesis_hash"), "norn.genesis_hash")
    if not HASH_RE.fullmatch(genesis):
        raise DeliveryError("norn.genesis_hash must be a lowercase bytes32 hash")
    if not template and genesis == "0x" + "0" * 64:
        raise DeliveryError("norn.genesis_hash is still a placeholder")
    _string(norn.get("registry_address"), "norn.registry_address", ADDRESS_RE)
    _string(norn.get("registry_key"), "norn.registry_key", IDENTIFIER_RE)
    _string(norn.get("schema_hash"), "norn.schema_hash", HASH_RE)
    _string(norn.get("snapshot_issuer"), "norn.snapshot_issuer", IDENTIFIER_RE)
    _string(norn.get("snapshot_key_id"), "norn.snapshot_key_id", IDENTIFIER_RE)
    _integer(norn.get("confirmations"), "norn.confirmations", 1, 100000)
    _integer(norn.get("registry_start_height"), "norn.registry_start_height", 0, 2**63 - 1)
    _integer(norn.get("max_scan_blocks"), "norn.max_scan_blocks", 1, 10_000_000)
    _string(norn.get("field_network"), "norn.field_network", HOST_RE)

    nodes = [_mapping(item, f"norn.nodes[{index}]") for index, item in enumerate(_array(norn.get("nodes"), "norn.nodes"))]
    if len(nodes) != 2 or {node.get("role") for node in nodes} != {"node-a", "node-b"}:
        raise DeliveryError("norn.nodes must contain exactly node-a and node-b")
    node_values: dict[str, list[str]] = {
        "host": [],
        "management_ip": [],
        "p2p_ip": [],
        "read_ip": [],
        "read_hostname": [],
        "data_dir": [],
        "config_dir": [],
        "tls_dir": [],
        "node_key_profile": [],
        "tls_profile": [],
    }
    for index, node in enumerate(nodes):
        label = f"norn.nodes[{index}]"
        _string(node.get("role"), f"{label}.role")
        for key in ("host", "read_hostname"):
            node_values[key].append(_string(node.get(key), f"{label}.{key}", HOST_RE))
        for key in ("management_ip", "p2p_ip", "read_ip"):
            node_values[key].append(_ip(node.get(key), f"{label}.{key}"))
        for key in ("data_dir", "config_dir", "tls_dir"):
            node_values[key].append(_absolute(node.get(key), f"{label}.{key}"))
        for key in ("node_key_profile", "tls_profile"):
            node_values[key].append(_string(node.get(key), f"{label}.{key}", IDENTIFIER_RE))
        _integer(node.get("native_loopback_port"), f"{label}.native_loopback_port", 1024, 65535)
    for key, values in node_values.items():
        _unique(values, f"Norn {key}")

    resolvers = [
        _mapping(item, f"resolvers[{index}]")
        for index, item in enumerate(_array(data.get("resolvers"), "resolvers"))
    ]
    if len(resolvers) < 1:
        raise DeliveryError("at least one resolver is required")
    if sum(resolver.get("role") == "first-hop" for resolver in resolvers) != 1:
        raise DeliveryError("exactly one first-hop resolver is required")
    resolver_unique: dict[str, list[str]] = {
        key: []
        for key in (
            "host",
            "server_id",
            "agent_key_id",
            "management_ip",
            "data_dir",
            "trace_socket",
            "secret_dir",
            "agent_tls_dir",
            "norn_tls_dir",
            "secret_profile",
            "tls_profile",
        )
    }
    for index, resolver in enumerate(resolvers):
        label = f"resolvers[{index}]"
        role = _string(resolver.get("role"), f"{label}.role")
        if role not in {"first-hop", "upstream"}:
            raise DeliveryError(f"{label}.role must be first-hop or upstream")
        resolver_unique["host"].append(_string(resolver.get("host"), f"{label}.host", HOST_RE))
        for key in ("server_id", "agent_key_id", "link_id"):
            value = _string(resolver.get(key), f"{label}.{key}", IDENTIFIER_RE)
            if key in resolver_unique:
                resolver_unique[key].append(value)
        resolver_unique["management_ip"].append(_ip(resolver.get("management_ip"), f"{label}.management_ip"))
        _absolute(
            resolver.get("existing_resolver_config"),
            f"{label}.existing_resolver_config",
        )
        _ip(resolver.get("dns_ip"), f"{label}.dns_ip")
        _ip(resolver.get("resolver_ip"), f"{label}.resolver_ip")
        resolver_unique["data_dir"].append(_absolute(resolver.get("data_dir"), f"{label}.data_dir"))
        resolver_unique["trace_socket"].append(_absolute(resolver.get("trace_socket"), f"{label}.trace_socket"))
        for key in ("secret_dir", "agent_tls_dir", "norn_tls_dir"):
            resolver_unique[key].append(
                _absolute(resolver.get(key), f"{label}.{key}")
            )
        resolver_unique["secret_profile"].append(_string(resolver.get("secret_profile"), f"{label}.secret_profile"))
        resolver_unique["tls_profile"].append(_string(resolver.get("tls_profile"), f"{label}.tls_profile"))
        _integer(resolver.get("trace_producer_uid"), f"{label}.trace_producer_uid", 1, 2**31 - 1)
        _integer(resolver.get("trace_producer_gid"), f"{label}.trace_producer_gid", 1, 2**31 - 1)
        upstreams = _array(resolver.get("wrapper_upstreams"), f"{label}.wrapper_upstreams")
        if role == "first-hop":
            expected_upstream = f"tcp://{resolver['resolver_ip']}:53"
            if upstreams != [expected_upstream]:
                raise DeliveryError(
                    "first-hop wrapper_upstreams must contain only the local "
                    f"Knot TCP endpoint {expected_upstream}"
                )
        elif upstreams:
            raise DeliveryError("upstream resolvers must not configure Wrapper upstreams")
    for key, values in resolver_unique.items():
        _unique(values, f"resolver {key}")

    all_hosts = [management_host, *node_values["host"], *resolver_unique["host"]]
    _unique(all_hosts, "server host")
    return data


def _quote(value: Any) -> str:
    text = str(value)
    if "\n" in text or "\r" in text or "'" in text:
        raise DeliveryError("environment value contains unsupported characters")
    return "'" + text + "'"


def _write_env(path: Path, values: dict[str, Any]) -> None:
    path.write_text(
        "\n".join(f"{key}={_quote(value)}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )


def _host_config(root: Path, host: str, kind: str, values: dict[str, Any], metadata: dict[str, Any]) -> None:
    config = root / "hosts" / host / "config"
    config.mkdir(parents=True)
    _write_env(config / ".env", values)
    (config / "host.json").write_text(
        json.dumps({"host": host, "package_kind": kind, **metadata}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if kind == "resolver-link":
        (config / "identities-v2.json").write_text('{"identities":[]}\n', encoding="utf-8")
        (config / "issuer-keys.json").write_text('{"keys":[]}\n', encoding="utf-8")
        shutil.copyfile(FIELD_ROOT / "resolver-link" / "kresd.conf", config / "kresd.conf")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_checksums(root: Path, paths: list[Path], destination: Path) -> None:
    lines = [f"{_sha256(path)}  {path.relative_to(root).as_posix()}" for path in sorted(paths)]
    destination.write_text("\n".join(lines) + "\n", encoding="ascii")


def _scan_package(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.lower().endswith(FORBIDDEN_SUFFIXES):
            raise DeliveryError(f"package contains a forbidden sensitive file: {relative}")
        content = path.read_bytes()
        if SECRET_CONTENT_RE.search(content):
            raise DeliveryError(f"package contains high-confidence secret material: {relative}")
        if LATEST_IMAGE_RE.search(content):
            raise DeliveryError(f"package contains a latest image reference: {relative}")


def _copy_package_source(
    kind: str,
    destination: Path,
    version: str,
    commit: str,
    production_trace_ready: bool,
) -> None:
    shutil.copytree(FIELD_ROOT / kind, destination)
    shutil.copytree(FIELD_ROOT / "common", destination / "common")
    for script in destination.rglob("*.sh"):
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    (destination / "PACKAGE-KIND").write_text(kind + "\n", encoding="ascii")
    (destination / "PACKAGE-VERSION").write_text(version + "\n", encoding="ascii")
    (destination / "PACKAGE-MANIFEST.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "package_kind": kind,
                "version": version,
                "git_commit": commit,
                "production_trace_ready": production_trace_ready,
                "p0_blockers": [] if production_trace_ready else [TRACE_BLOCKER],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    checksum_paths = [
        path
        for path in destination.rglob("*")
        if path.is_file() and path.name != "PACKAGE-SHA256SUMS"
    ]
    _write_checksums(destination, checksum_paths, destination / "PACKAGE-SHA256SUMS")
    _scan_package(destination)


def _tar_reproducible(source: Path, destination: Path) -> None:
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted([source, *source.rglob("*")]):
                    relative = Path(source.name) / path.relative_to(source)
                    info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 0
                    if path.is_file():
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        archive.addfile(info)


def _render_host_configs(inventory: dict[str, Any], release_root: Path) -> None:
    release = inventory["release"]
    images = release["images"]
    management = inventory["management"]
    norn = inventory["norn"]
    network = norn["field_network"]
    read_urls = ",".join(f"https://{node['read_hostname']}:8443" for node in norn["nodes"])
    node_a = next(node for node in norn["nodes"] if node["role"] == "node-a")

    _host_config(
        release_root,
        management["host"],
        "management",
        {
            "RI_FIELD_HOST_ID": management["host"],
            "RI_FIELD_COMPOSE_PROJECT": management["host"],
            "RI_FIELD_NETWORK": network,
            "RI_FIELD_DATA_DIR": management["data_dir"],
            "RI_MANAGEMENT_IMAGE": images["management"],
            "RI_NORN_IMAGE": images["norn"],
            "RI_MANAGEMENT_WORK_DIR": management["work_dir"],
            "RI_MANAGEMENT_SECRET_DIR": management["secret_dir"],
            "RI_NORNCTL_TLS_DIR": management["norn_tls_dir"],
            "RI_NORN_PUBLISH_MODE": "ssh-tunnel",
            "RI_NORN_PUBLISH_TARGET": "127.0.0.1:45555",
            "RI_NORN_SIMULATION_PUBLISH_TARGET": f"{node_a['host']}:45555",
        },
        {"role": "management", "management_ip": management["management_ip"]},
    )

    for node in norn["nodes"]:
        bootstrap = ""
        if node["role"] == "node-b":
            bootstrap = f"/dns4/{node_a['host']}/tcp/31258/p2p/<NODE_A_PEER_ID>"
        _host_config(
            release_root,
            node["host"],
            "norn-node",
            {
                "RI_FIELD_HOST_ID": node["host"],
                "RI_FIELD_COMPOSE_PROJECT": f"ri-{node['host']}",
                "RI_FIELD_NETWORK": network,
                "RI_FIELD_DATA_DIR": node["data_dir"],
                "RI_NORN_IMAGE": images["norn"],
                "RI_NGINX_IMAGE": images["nginx"],
                "RI_NORN_ROLE": node["role"],
                "RI_NORN_NODE_HOSTNAME": node["host"],
                "RI_NORN_READ_HOSTNAME": node["read_hostname"],
                "RI_NORN_CONFIG_DIR": node["config_dir"],
                "RI_NORN_TLS_DIR": node["tls_dir"],
                "RI_NORN_NATIVE_BIND_ADDRESS": "127.0.0.1",
                "RI_NORN_NATIVE_LOOPBACK_PORT": node["native_loopback_port"],
                "RI_NORN_P2P_BIND_ADDRESS": node["p2p_ip"],
                "RI_NORN_READ_BIND_ADDRESS": node["read_ip"],
                "RI_NORN_READ_PORT": 8443,
                "RI_NORN_BOOTSTRAP": bootstrap,
                "RI_NORN_UID": 10003,
                "RI_NORN_GID": 10003,
            },
            {
                "role": node["role"],
                "management_ip": node["management_ip"],
                "p2p_ip": node["p2p_ip"],
                "read_ip": node["read_ip"],
                "node_key_profile": node["node_key_profile"],
                "tls_profile": node["tls_profile"],
            },
        )

    for resolver in inventory["resolvers"]:
        upstreams = ",".join(resolver["wrapper_upstreams"])
        _host_config(
            release_root,
            resolver["host"],
            "resolver-link",
            {
                "RI_FIELD_HOST_ID": resolver["host"],
                "RI_FIELD_COMPOSE_PROJECT": f"ri-{resolver['host'].lower()}",
                "RI_FIELD_NETWORK": network,
                "RI_FIELD_DATA_DIR": resolver["data_dir"],
                "RI_MANAGEMENT_BIND_ADDRESS": resolver["management_ip"],
                "RI_IMAGE": images["rust"],
                "RI_KNOT_IMAGE": images["knot"],
                "RI_RESOLVER_ROLE": resolver["role"],
                "RI_VERIFICATION_MODE": "controlled-strict",
                "RI_AGENT_SERVER_ID": resolver["server_id"],
                "RI_AGENT_KEY_ID": resolver["agent_key_id"],
                "RI_CHAIN_ADAPTER": "norn",
                "RI_CHAIN_RPC_URLS": read_urls,
                "RI_CHAIN_ID": norn["chain_id"],
                "RI_NORN_GENESIS_BLOCK_HASH": norn["genesis_hash"],
                "RI_CHAIN_REGISTRY_ADDRESS": norn["registry_address"],
                "RI_NORN_REGISTRY_KEY": norn["registry_key"],
                "RI_NORN_SIGNER_ISSUER": norn["snapshot_issuer"],
                "RI_NORN_SIGNER_KEY_ID": norn["snapshot_key_id"],
                "RI_CHAIN_REGISTRY_SCHEMA_HASH": norn["schema_hash"],
                "RI_CHAIN_CONFIRMATIONS": norn["confirmations"],
                "RI_NORN_REGISTRY_START_HEIGHT": norn["registry_start_height"],
                "RI_NORN_MAX_SCAN_BLOCKS": norn["max_scan_blocks"],
                "RI_NORN_CLIENT_TLS_DIR": resolver["norn_tls_dir"],
                "RI_RESOLVER_SECRET_DIR": resolver["secret_dir"],
                "RI_AGENT_TLS_DIR": resolver["agent_tls_dir"],
                "RI_TRACE_SOCKET_HOST_DIR": resolver["trace_socket"],
                "RI_TRACE_PRODUCER_UID": resolver["trace_producer_uid"],
                "RI_TRACE_PRODUCER_GID": resolver["trace_producer_gid"],
                "RI_KNOT_RESOLVER_UID": 10003,
                "RI_EXISTING_RESOLVER_CONFIG_PATH": resolver[
                    "existing_resolver_config"
                ],
                "RI_RESOLVER_BIND_ADDRESS": resolver["resolver_ip"],
                "RI_TRACE_MAX_CONTEXTS": 65536,
                "RI_TRACE_ACK_TIMEOUT_MS": 100,
                "RI_TRACE_CACHE_PROVENANCE_WAIT_MS": 2000,
                "RI_TRACE_WAIT_MILLIS": 5000,
                "RI_WRAPPER_AGENT_TIMEOUT_MS": 7500,
                "RI_WRAPPER_MAX_CONCURRENT_VERIFICATIONS": 32,
                "RI_WRAPPER_UPSTREAMS": upstreams,
                "DNS_BIND_ADDRESS": resolver["dns_ip"],
                "DNS_PORT": 53,
                "RI_REGISTRY_SYNC_ONCE": "false",
            },
            {
                "role": resolver["role"],
                "link_id": resolver["link_id"],
                "server_id": resolver["server_id"],
                "management_ip": resolver["management_ip"],
                "resolver_ip": resolver["resolver_ip"],
                "secret_profile": resolver["secret_profile"],
                "tls_profile": resolver["tls_profile"],
                "resolver": TRACE_RESOLVER_NAME,
                "resolver_version": TRACE_RESOLVER_VERSION,
            },
        )


def _secret_requirements(inventory: dict[str, Any]) -> dict[str, Any]:
    hosts: dict[str, Any] = {}
    management = inventory["management"]
    hosts[management["host"]] = {
        "package_kind": "management",
        "mount_root": management["secret_dir"],
        "required": [
            "identity-issuer-ed25519-private-key",
            "snapshot-issuer-ed25519-private-key",
            "publication-ssh-identity",
        ],
        "generated_by_renderer": False,
    }
    for node in inventory["norn"]["nodes"]:
        hosts[node["host"]] = {
            "package_kind": "norn-node",
            "node_key_profile": node["node_key_profile"],
            "tls_profile": node["tls_profile"],
            "required": [
                "config.yml-with-unique-consensus-key",
                "server.crt",
                "server.key",
                "ca.crt",
            ],
            "generated_by_renderer": False,
        }
    for resolver in inventory["resolvers"]:
        hosts[resolver["host"]] = {
            "package_kind": "resolver-link",
            "secret_profile": resolver["secret_profile"],
            "tls_profile": resolver["tls_profile"],
            "required": [
                "agent_private_key",
                "trace_ingest_token",
                "agent_wrapper_token",
                "agent_peer_token",
                "agent-mTLS-material",
                "norn-read-client-mTLS-material",
            ],
            "generated_by_renderer": False,
        }
    return {"schema_version": 1, "hosts": hosts}


def _network_matrix(inventory: dict[str, Any]) -> dict[str, Any]:
    management = inventory["management"]["host"]
    nodes = inventory["norn"]["nodes"]
    resolvers = inventory["resolvers"]
    rules: list[dict[str, Any]] = [
        {"source": management, "destination": nodes[0]["host"], "protocol": "tcp", "port": 22, "purpose": "authenticated SSH publication tunnel"},
        {"source": nodes[0]["host"], "destination": nodes[1]["host"], "protocol": "tcp", "port": 31258, "purpose": "Go-Norn peer traffic"},
        {"source": nodes[1]["host"], "destination": nodes[0]["host"], "protocol": "tcp", "port": 31258, "purpose": "Go-Norn peer traffic"},
    ]
    for resolver in resolvers:
        for node in nodes:
            rules.append(
                {
                    "source": resolver["host"],
                    "destination": node["read_hostname"],
                    "protocol": "tcp",
                    "port": 8443,
                    "purpose": "mTLS Registry Sync read",
                }
            )
    first = next(resolver for resolver in resolvers if resolver["role"] == "first-hop")
    rules.append({"source": "dns-clients", "destination": first["host"], "protocol": "udp/tcp", "port": 53, "purpose": "DNS entry"})
    return {
        "schema_version": 1,
        "default_policy": "deny",
        "rules": rules,
        "explicit_denies": [
            "resolver-link to native Norn gRPC",
            "Agent or Wrapper to any Norn endpoint",
            "upstream Wrapper service",
            "Norn write method through read proxy",
        ],
    }


def _installation_order(inventory: dict[str, Any]) -> str:
    resolver_hosts = ", ".join(resolver["host"] for resolver in inventory["resolvers"])
    return f"""# Installation order

1. Install `{inventory['management']['host']}` and verify offline identity/snapshot tooling.
2. Install Node A, generate its unique node key and mTLS material, then wait for genesis.
3. Record Node A's peer ID; install Node B as an independent read replica without `-g`.
4. Verify both read-only proxies reject every method except the three approved read RPCs.
5. Pin the observed genesis in Inventory and re-render resolver configuration.
6. Generate and publish the signed snapshot through the authenticated SSH publication tunnel.
7. Install resolver Registry Sync instances on `{resolver_hosts}` and verify independent SQLite files.
8. Install Agent and Trace Adapter on every resolver host.
9. Install Wrapper only on the `first-hop` host.

Do not cut DNS traffic until the release manifest records a script-generated,
successful production Resolver Trace acceptance result.
"""


def _trace_acceptance_ready(path: Path | None, commit: str) -> bool:
    if path is None:
        return False
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DeliveryError(f"cannot read Trace acceptance evidence: {error}") from error
    expected = {
        "schema_version": TRACE_ACCEPTANCE_SCHEMA,
        "source_commit": commit,
        "resolver_name": TRACE_RESOLVER_NAME,
        "resolver_version": TRACE_RESOLVER_VERSION,
        "resolver_upstream_commit": TRACE_RESOLVER_COMMIT,
        "production_trace_ready": True,
        "generated_by": "tools/run_production_trace_acceptance.py",
        "secret_scan_clean": True,
    }
    for key, value in expected.items():
        if evidence.get(key) != value:
            raise DeliveryError(f"Trace acceptance field {key} is not approved")
    results = evidence.get("results")
    if (
        not isinstance(results, dict)
        or not results
        or not TRACE_REQUIRED_RESULTS.issubset(results)
        or any(value != "passed" for value in results.values())
    ):
        raise DeliveryError("Trace acceptance does not contain an all-passed result set")
    if evidence.get("cross_talk_count") != 0:
        raise DeliveryError("Trace acceptance detected cross-talk")
    if evidence.get("time_window_matching") is not False:
        raise DeliveryError("Trace acceptance did not disable time-window matching")
    if evidence.get("failure_closed") is not True:
        raise DeliveryError("Trace acceptance did not prove failure-closed behavior")
    return True


def render(
    inventory: dict[str, Any],
    output_root: Path,
    *,
    force: bool = False,
    offline_image_dir: Path | None = None,
    trace_acceptance: Path | None = None,
) -> Path:
    validate_inventory(inventory)
    version = inventory["release"]["version"]
    commit = inventory["release"]["git_commit"]
    try:
        actual_commit = subprocess.check_output(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise DeliveryError(f"cannot determine repository commit: {error}") from error
    if actual_commit != commit:
        raise DeliveryError(f"inventory commit {commit} does not match source {actual_commit}")
    production_trace_ready = _trace_acceptance_ready(trace_acceptance, commit)

    release_root = output_root.resolve() / version
    if release_root.exists():
        if not force:
            raise DeliveryError(f"output already exists: {release_root}")
        shutil.rmtree(release_root)
    release_root.mkdir(parents=True)
    _render_host_configs(inventory, release_root)

    package_records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ri-field-packages-") as temporary:
        build_root = Path(temporary)
        for kind in PACKAGE_KINDS:
            package_name = f"resolver-identity-{kind}-{version}"
            source = build_root / package_name
            _copy_package_source(kind, source, version, commit, production_trace_ready)
            tar_path = release_root / f"{package_name}.tar.gz"
            _tar_reproducible(source, tar_path)
            package_records.append(
                {
                    "kind": kind,
                    "filename": tar_path.name,
                    "sha256": _sha256(tar_path),
                }
            )

    secrets = _secret_requirements(inventory)
    network = _network_matrix(inventory)
    (release_root / "secret-requirements.json").write_text(json.dumps(secrets, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (release_root / "network-matrix.json").write_text(json.dumps(network, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (release_root / "installation-order.md").write_text(_installation_order(inventory), encoding="utf-8")

    image_archives: list[dict[str, Any]] = []
    if offline_image_dir is not None:
        destination = release_root / "offline-images"
        destination.mkdir()
        for key in IMAGE_KEYS:
            source = offline_image_dir / f"{key}.tar"
            if not source.is_file():
                raise DeliveryError(f"offline image archive is missing: {source}")
            target = destination / source.name
            shutil.copyfile(source, target)
            image_archives.append({"image": inventory["release"]["images"][key], "filename": target.name, "sha256": _sha256(target)})
        (destination / "image-archives.json").write_text(
            json.dumps({"schema_version": 1, "archives": image_archives}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    manifest = {
        "schema_version": "resolver-identity-norn-field-release-v1",
        "version": version,
        "git_commit": commit,
        "packages": package_records,
        "images": inventory["release"]["images"],
        "delivery_modes": {
            "internal_registry": True,
            "offline_image_archives": True,
            "offline_archives_included": offline_image_dir is not None,
        },
        "simulated_server_count": 1 + len(inventory["norn"]["nodes"]) + len(inventory["resolvers"]),
        "resolver_trace": {
            "resolver": TRACE_RESOLVER_NAME,
            "version": TRACE_RESOLVER_VERSION,
            "upstream_commit": TRACE_RESOLVER_COMMIT,
        },
        "production_trace_ready": production_trace_ready,
        "p0_blockers": [] if production_trace_ready else [TRACE_BLOCKER],
        "deployment_status": "field-delivery-candidate-not-production-deployed",
    }
    (release_root / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    host_paths = [path for path in (release_root / "hosts").rglob("*") if path.is_file()]
    _write_checksums(release_root, host_paths, release_root / "hosts" / "SHA256SUMS")
    checksum_names = [
        *(release_root / record["filename"] for record in package_records),
        release_root / "release-manifest.json",
        release_root / "network-matrix.json",
        release_root / "secret-requirements.json",
        release_root / "installation-order.md",
        release_root / "hosts" / "SHA256SUMS",
    ]
    if offline_image_dir is not None:
        checksum_names.extend(path for path in (release_root / "offline-images").iterdir() if path.is_file())
    _write_checksums(release_root, checksum_names, release_root / "SHA256SUMS")
    return release_root


def verify_release(path: Path) -> dict[str, Any]:
    root = path.resolve()
    manifest_path = root / "release-manifest.json"
    checksums = root / "SHA256SUMS"
    if not manifest_path.is_file() or not checksums.is_file():
        raise DeliveryError("release manifest or SHA256SUMS is missing")
    subprocess.run(["sha256sum", "--check", "--strict", str(checksums)], cwd=root, check=True, stdout=subprocess.DEVNULL)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_ready = manifest.get("production_trace_ready")
    blockers = manifest.get("p0_blockers")
    if not isinstance(trace_ready, bool) or not isinstance(blockers, list):
        raise DeliveryError("release Trace readiness metadata is malformed")
    if trace_ready == bool(blockers):
        raise DeliveryError("release Trace readiness and blockers are inconsistent")
    expected = {record["filename"] for record in manifest.get("packages", [])}
    actual = {path.name for path in root.glob("resolver-identity-*.tar.gz")}
    if expected != actual or len(expected) != 3:
        raise DeliveryError("release package set is incomplete")
    for archive in root.glob("resolver-identity-*.tar.gz"):
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            for member in members:
                path = Path(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise DeliveryError(f"unsafe archive path: {member.name}")
                if member.isfile() and member.name.lower().endswith(FORBIDDEN_SUFFIXES):
                    raise DeliveryError(f"sensitive file in archive: {member.name}")
    return manifest


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--inventory", type=Path, required=True)
    validate_parser.add_argument("--template", action="store_true")
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("--inventory", type=Path, required=True)
    render_parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "artifacts" / "field-deployment")
    render_parser.add_argument("--force", action="store_true")
    render_parser.add_argument("--offline-image-dir", type=Path)
    render_parser.add_argument("--trace-acceptance", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--release", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            validate_inventory(load_inventory(args.inventory), template=args.template)
            print("inventory valid")
        elif args.command == "render":
            output = render(
                load_inventory(args.inventory),
                args.output_root,
                force=args.force,
                offline_image_dir=args.offline_image_dir,
                trace_acceptance=args.trace_acceptance,
            )
            print(output)
        else:
            manifest = verify_release(args.release)
            print(json.dumps({"verified": True, "version": manifest["version"]}))
    except (DeliveryError, OSError, subprocess.CalledProcessError) as error:
        print(f"field delivery error: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
