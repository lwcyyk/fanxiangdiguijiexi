#!/usr/bin/env python3
"""Validate a domain-center inventory and render isolated Rust link bundles."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shlex
import shutil
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_SOURCE = REPO_ROOT / "deploy/link/docker-compose.yml"
RUNTIME_SCRIPTS = (
    "03-install-link.sh",
    "04-start-link.sh",
    "05-acceptance-test.sh",
    "06-isolation-test.sh",
    "07-backup-link.sh",
    "08-restore-drill.sh",
    "09-capacity-test.sh",
    "10-collect-evidence.sh",
)
SECRET_FILES = (
    "agent_private_key",
    "trace_ingest_token",
    "agent_wrapper_token",
    "agent_peer_token",
)
TLS_FILES = (
    "agent.crt",
    "agent.key",
    "client-ca.crt",
    "wrapper-client.crt",
    "wrapper-client.key",
    "trace-client.crt",
    "trace-client.key",
    "agent-client.crt",
    "agent-client.key",
    "agent-ca.crt",
)
TLS_PRIVATE_FILES = (
    "agent.key",
    "wrapper-client.key",
    "trace-client.key",
    "agent-client.key",
)
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)
PLACEHOLDER_PATTERN = re.compile(
    r"(?:<[^>]+>|example\.invalid|replace[_ -]?with|todo|changeme)", re.IGNORECASE
)
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_PATTERN = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


class InventoryError(ValueError):
    """Raised when a field deployment inventory is unsafe or incomplete."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot load JSON file {path}: {error}") from error


def _load_verified_identities(identity_path: Path, issuer_path: Path) -> list[dict[str, Any]]:
    source_root = str(REPO_ROOT / "src")
    repository_root = str(REPO_ROOT)
    for import_root in (source_root, repository_root):
        if import_root not in sys.path:
            sys.path.insert(0, import_root)
    try:
        from tools.manage_v2_registry import load_identities

        return load_identities(identity_path, issuer_path)
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise InventoryError(f"identity signature or structure validation failed: {error}") from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise InventoryError(f"{label} must be an array")
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise InventoryError(f"{label} must be a non-empty string")
    return value.strip()


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InventoryError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _required(mapping: dict[str, Any], key: str, label: str) -> Any:
    if key not in mapping:
        raise InventoryError(f"{label}.{key} is required")
    return mapping[key]


def _strict_string(value: Any, label: str) -> str:
    result = _string(value, label)
    if PLACEHOLDER_PATTERN.search(result):
        raise InventoryError(f"{label} contains a placeholder")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise InventoryError(f"{label} contains a control character")
    return result


def _validate_ip(value: Any, label: str, *, allow_loopback: bool = False) -> str:
    text = _strict_string(value, label)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise InventoryError(f"{label} must be an IP address") from error
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise InventoryError(f"{label} is not a deployable unicast address")
    if address.is_loopback and not allow_loopback:
        raise InventoryError(f"{label} must not be a loopback address")
    if any(address in network for network in DOCUMENTATION_NETWORKS):
        raise InventoryError(f"{label} must not use a documentation address")
    return address.compressed


def _validate_https_url(value: Any, label: str) -> str:
    text = _strict_string(value, label)
    parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname:
        raise InventoryError(f"{label} must be an HTTPS URL")
    if parsed.username or parsed.password:
        raise InventoryError(f"{label} must not contain authority credentials")
    if parsed.hostname.endswith(".invalid"):
        raise InventoryError(f"{label} uses an invalid host")
    return text


def _validate_agent_url(value: Any, label: str) -> tuple[str, str, int]:
    text = _validate_https_url(value, label)
    parsed = urlsplit(text)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise InventoryError(f"{label} must be an HTTPS origin without a path or query")
    return text.rstrip("/"), parsed.hostname or "", parsed.port or 443


def _validate_nonzero_hex(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    text = _strict_string(value, label)
    if not pattern.fullmatch(text):
        raise InventoryError(f"{label} has an invalid hexadecimal length")
    if int(text, 16) == 0:
        raise InventoryError(f"{label} must not be zero")
    return text.lower()


def _validate_path(value: Any, label: str, *, must_exist: bool) -> Path:
    path = Path(_strict_string(value, label)).expanduser()
    if not path.is_absolute():
        raise InventoryError(f"{label} must be an absolute path")
    if path.is_symlink():
        raise InventoryError(f"{label} must not be a symbolic link")
    if must_exist and not path.is_file():
        raise InventoryError(f"{label} does not exist or is not a file")
    return path


def _validate_identifier(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    text = _strict_string(value, label)
    if not pattern.fullmatch(text):
        raise InventoryError(f"{label} contains unsupported characters")
    return text


def _validate_material_file(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise InventoryError(f"{label} must not be a symbolic link")
    if not path.is_file():
        raise InventoryError(f"{label} is missing: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise InventoryError(f"{label} must not be accessible by group or others")
    content = path.read_bytes().strip()
    if len(content) < 32:
        raise InventoryError(f"{label} must contain at least 32 bytes")
    return content


def _parse_upstream(value: Any, label: str) -> tuple[str, str, int]:
    text = _strict_string(value, label)
    parsed = urlsplit(text)
    if parsed.scheme not in {"udp", "tcp"} or parsed.path or parsed.query or parsed.fragment:
        raise InventoryError(f"{label} must use udp://IP:port or tcp://IP:port")
    if parsed.username or parsed.password or not parsed.hostname or parsed.port is None:
        raise InventoryError(f"{label} must include only an IP address and port")
    host = _validate_ip(parsed.hostname, f"{label} host")
    port = _integer(parsed.port, f"{label} port", 1, 65535)
    return text, host, port


def _template_shape(data: dict[str, Any]) -> None:
    if data.get("schema_version") != 1:
        raise InventoryError("schema_version must be 1")
    _string(_required(data, "site_id", "inventory"), "site_id")
    _string(_required(data, "change_ticket", "inventory"), "change_ticket")
    release = _mapping(_required(data, "release", "inventory"), "release")
    _string(_required(release, "git_commit", "release"), "release.git_commit")
    _string(_required(release, "image", "release"), "release.image")
    registry = _mapping(_required(data, "registry", "inventory"), "registry")
    for key in ("network_name", "rpc_url", "contract_address", "runtime_code_hash"):
        _string(_required(registry, key, "registry"), f"registry.{key}")
    _integer(_required(registry, "chain_id", "registry"), "registry.chain_id", 1, 2**63 - 1)
    _integer(
        _required(registry, "fallback_confirmations", "registry"),
        "registry.fallback_confirmations",
        0,
        100_000,
    )
    _integer(
        _required(registry, "max_staleness_seconds", "registry"),
        "registry.max_staleness_seconds",
        1,
        86_400,
    )
    artifacts = _mapping(_required(data, "artifacts", "inventory"), "artifacts")
    for key in ("identities_file", "issuer_keys_file"):
        _string(_required(artifacts, key, "artifacts"), f"artifacts.{key}")
    hub = _mapping(_required(data, "hub", "inventory"), "hub")
    for key in (
        "management_host",
        "operations_host",
        "test_client_host",
        "prometheus_ip",
        "log_collector_ip",
        "bastion_ip",
        "backup_target",
    ):
        _string(_required(hub, key, "hub"), f"hub.{key}")
    units = _list(_required(data, "units", "inventory"), "units")
    if not units:
        raise InventoryError("units must contain at least one link unit")
    required_unit_fields = (
        "link_id",
        "unit_id",
        "role",
        "hostname",
        "management_ip",
        "compose_project",
        "verification_mode",
        "agent_server_id",
        "agent_key_id",
        "trace_producer_uid",
        "trace_producer_gid",
        "trace_socket_host_dir",
        "wrapper_ip",
        "dns_port",
        "resolver_upstreams",
        "agent_bind_address",
        "agent_port",
        "metrics_bind_address",
        "metrics_ports",
        "remote_release_root",
        "private_material_dir",
        "shadow_test_name",
        "rollback_target",
    )
    for index, raw_unit in enumerate(units):
        unit = _mapping(raw_unit, f"units[{index}]")
        for key in required_unit_fields:
            _required(unit, key, f"units[{index}]")
        for key in (
            "link_id",
            "unit_id",
            "role",
            "hostname",
            "management_ip",
            "compose_project",
            "verification_mode",
            "agent_server_id",
            "agent_key_id",
            "trace_socket_host_dir",
            "wrapper_ip",
            "agent_bind_address",
            "metrics_bind_address",
            "remote_release_root",
            "private_material_dir",
            "shadow_test_name",
            "rollback_target",
        ):
            _string(unit[key], f"units[{index}].{key}")
        _integer(unit["trace_producer_uid"], f"units[{index}].trace_producer_uid", 1, 2**31 - 1)
        _integer(unit["trace_producer_gid"], f"units[{index}].trace_producer_gid", 1, 2**31 - 1)
        _integer(unit["dns_port"], f"units[{index}].dns_port", 1, 65535)
        _integer(unit["agent_port"], f"units[{index}].agent_port", 1, 65535)
        upstreams = _list(unit["resolver_upstreams"], f"units[{index}].resolver_upstreams")
        if not upstreams:
            raise InventoryError(f"units[{index}].resolver_upstreams must not be empty")
        for upstream_index, upstream in enumerate(upstreams):
            _string(upstream, f"units[{index}].resolver_upstreams[{upstream_index}]")
        metrics = _mapping(unit["metrics_ports"], f"units[{index}].metrics_ports")
        for key in ("wrapper", "registry", "trace"):
            _integer(_required(metrics, key, "metrics_ports"), f"metrics_ports.{key}", 1, 65535)


def validate_inventory(data: Any, *, template: bool = False, check_materials: bool = True) -> dict[str, Any]:
    inventory = _mapping(data, "inventory")
    _template_shape(inventory)
    if template:
        return inventory

    site_id = _validate_identifier(inventory["site_id"], "site_id", IDENTIFIER_PATTERN)
    _strict_string(inventory["change_ticket"], "change_ticket")
    release = _mapping(inventory["release"], "release")
    git_commit = _strict_string(release["git_commit"], "release.git_commit").lower()
    if not GIT_COMMIT_PATTERN.fullmatch(git_commit):
        raise InventoryError("release.git_commit must be a full 40-character commit")
    image = _strict_string(release["image"], "release.image")
    if not IMAGE_PATTERN.fullmatch(image):
        raise InventoryError("release.image must be fixed to a sha256 digest")

    registry = _mapping(inventory["registry"], "registry")
    network_name = _strict_string(registry["network_name"], "registry.network_name")
    chain_id = _integer(registry["chain_id"], "registry.chain_id", 1, 2**63 - 1)
    if chain_id == 1 or network_name.lower() in {"mainnet", "ethereum-mainnet"}:
        raise InventoryError("Ethereum Mainnet is forbidden")
    _validate_https_url(registry["rpc_url"], "registry.rpc_url")
    _validate_nonzero_hex(registry["contract_address"], "registry.contract_address", ADDRESS_PATTERN)
    _validate_nonzero_hex(registry["runtime_code_hash"], "registry.runtime_code_hash", HASH_PATTERN)

    artifacts = _mapping(inventory["artifacts"], "artifacts")
    identities_path = _validate_path(
        artifacts["identities_file"], "artifacts.identities_file", must_exist=check_materials
    )
    issuer_keys_path = _validate_path(
        artifacts["issuer_keys_file"], "artifacts.issuer_keys_file", must_exist=check_materials
    )

    hub = _mapping(inventory["hub"], "hub")
    for key in ("management_host", "operations_host", "test_client_host", "backup_target"):
        _strict_string(hub[key], f"hub.{key}")
    for key in ("prometheus_ip", "log_collector_ip", "bastion_ip"):
        _validate_ip(hub[key], f"hub.{key}")

    identity_by_server: dict[str, dict[str, Any]] = {}
    if check_materials:
        for index, raw_identity in enumerate(
            _load_verified_identities(identities_path, issuer_keys_path)
        ):
            identity = _mapping(raw_identity, f"verified identities[{index}]")
            server_id = _string(identity.get("server_id"), f"identities[{index}].server_id")
            if server_id in identity_by_server:
                raise InventoryError(f"duplicate identity server_id: {server_id}")
            identity_by_server[server_id] = identity

    seen_values: dict[str, set[str]] = {
        "unit_id": set(),
        "compose_project": set(),
        "agent_server_id": set(),
        "agent_key_id": set(),
        "wrapper_ip": set(),
    }
    host_sockets: set[tuple[str, str]] = set()
    host_ports: set[tuple[str, str, int, str]] = set()
    secret_digests: dict[str, tuple[str, str, str]] = {}
    tls_key_digests: dict[str, str] = {}

    for index, raw_unit in enumerate(_list(inventory["units"], "units")):
        unit = _mapping(raw_unit, f"units[{index}]")
        prefix = f"units[{index}]"
        link_id = _validate_identifier(unit["link_id"], f"{prefix}.link_id", IDENTIFIER_PATTERN)
        unit_id = _validate_identifier(unit["unit_id"], f"{prefix}.unit_id", IDENTIFIER_PATTERN)
        role = _strict_string(unit["role"], f"{prefix}.role")
        if role not in {"entry", "upstream"}:
            raise InventoryError(f"{prefix}.role must be entry or upstream")
        hostname = _validate_identifier(unit["hostname"], f"{prefix}.hostname", IDENTIFIER_PATTERN)
        project = _validate_identifier(
            unit["compose_project"], f"{prefix}.compose_project", PROJECT_PATTERN
        )
        mode = _strict_string(unit["verification_mode"], f"{prefix}.verification_mode")
        if mode not in {"public-hybrid", "controlled-strict"}:
            raise InventoryError(f"{prefix}.verification_mode is unsupported")
        server_id = _strict_string(unit["agent_server_id"], f"{prefix}.agent_server_id")
        key_id = _strict_string(unit["agent_key_id"], f"{prefix}.agent_key_id")
        management_ip = _validate_ip(unit["management_ip"], f"{prefix}.management_ip")
        wrapper_ip = _validate_ip(unit["wrapper_ip"], f"{prefix}.wrapper_ip")
        agent_bind = _validate_ip(
            unit["agent_bind_address"], f"{prefix}.agent_bind_address", allow_loopback=True
        )
        metrics_bind = _validate_ip(
            unit["metrics_bind_address"], f"{prefix}.metrics_bind_address", allow_loopback=True
        )
        trace_socket = _strict_string(unit["trace_socket_host_dir"], f"{prefix}.trace_socket_host_dir")
        if not Path(trace_socket).is_absolute() or not trace_socket.startswith(
            "/run/resolver-identity/"
        ):
            raise InventoryError(
                f"{prefix}.trace_socket_host_dir must be under /run/resolver-identity"
            )
        remote_root = _strict_string(unit["remote_release_root"], f"{prefix}.remote_release_root")
        if not Path(remote_root).is_absolute():
            raise InventoryError(f"{prefix}.remote_release_root must be absolute")
        shadow_test_name = _strict_string(
            unit["shadow_test_name"], f"{prefix}.shadow_test_name"
        )
        if not re.fullmatch(
            r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?",
            shadow_test_name,
        ):
            raise InventoryError(f"{prefix}.shadow_test_name must be a valid FQDN")
        _strict_string(unit["rollback_target"], f"{prefix}.rollback_target")

        for key, value in (
            ("unit_id", unit_id),
            ("compose_project", project),
            ("agent_server_id", server_id),
            ("agent_key_id", key_id),
            ("wrapper_ip", wrapper_ip),
        ):
            if value in seen_values[key]:
                raise InventoryError(f"{prefix}.{key} is not unique: {value}")
            seen_values[key].add(value)

        socket_key = (hostname, trace_socket)
        if socket_key in host_sockets:
            raise InventoryError(f"{prefix}.trace_socket_host_dir conflicts on {hostname}")
        host_sockets.add(socket_key)

        dns_port = _integer(unit["dns_port"], f"{prefix}.dns_port", 1, 65535)
        agent_port = _integer(unit["agent_port"], f"{prefix}.agent_port", 1, 65535)
        metrics = _mapping(unit["metrics_ports"], f"{prefix}.metrics_ports")
        port_bindings = (
            (wrapper_ip, dns_port, "udp"),
            (wrapper_ip, dns_port, "tcp"),
            (agent_bind, agent_port, "tcp"),
            (
                metrics_bind,
                _integer(metrics["wrapper"], f"{prefix}.metrics_ports.wrapper", 1, 65535),
                "tcp",
            ),
            (
                metrics_bind,
                _integer(metrics["registry"], f"{prefix}.metrics_ports.registry", 1, 65535),
                "tcp",
            ),
            (
                metrics_bind,
                _integer(metrics["trace"], f"{prefix}.metrics_ports.trace", 1, 65535),
                "tcp",
            ),
        )
        for bind, port, protocol in port_bindings:
            key = (hostname, bind, port, protocol)
            if key in host_ports:
                raise InventoryError(f"{prefix} has a host port conflict: {bind}:{port}/{protocol}")
            host_ports.add(key)

        upstreams = _list(unit["resolver_upstreams"], f"{prefix}.resolver_upstreams")
        transports: set[str] = set()
        for upstream_index, upstream_value in enumerate(upstreams):
            upstream, upstream_host, _ = _parse_upstream(
                upstream_value, f"{prefix}.resolver_upstreams[{upstream_index}]"
            )
            transports.add(urlsplit(upstream).scheme)
            if upstream_host == wrapper_ip:
                raise InventoryError(f"{prefix} resolver upstream points back to the Wrapper")
        if role == "entry" and transports != {"udp", "tcp"}:
            raise InventoryError(f"{prefix} entry unit requires both UDP and TCP upstreams")

        if check_materials:
            identity = identity_by_server.get(server_id)
            if identity is None:
                raise InventoryError(f"{prefix}.agent_server_id has no signed identity")
            agent = _mapping(identity.get("agent"), f"identity {server_id}.agent")
            if agent.get("key_id") != key_id:
                raise InventoryError(f"{prefix}.agent_key_id does not match its identity")
            (
                unit["_agent_service_url"],
                unit["_agent_tls_server_name"],
                unit["_agent_service_port"],
            ) = _validate_agent_url(
                agent.get("service_url"),
                f"identity {server_id}.agent.service_url",
            )

            material_dir = Path(
                _strict_string(unit["private_material_dir"], f"{prefix}.private_material_dir")
            ).expanduser()
            if not material_dir.is_absolute():
                raise InventoryError(f"{prefix}.private_material_dir must be absolute")
            if material_dir.is_symlink():
                raise InventoryError(f"{prefix}.private_material_dir must not be a symbolic link")
            unit_secret_digests: dict[str, str] = {}
            for secret_name in SECRET_FILES:
                content = _validate_material_file(
                    material_dir / "secrets" / secret_name,
                    f"{prefix} {secret_name}",
                )
                digest = hashlib.sha256(content).hexdigest()
                unit_secret_digests[secret_name] = digest
                previous = secret_digests.get(digest)
                if previous:
                    previous_link, previous_name, previous_label = previous
                    if (
                        secret_name != "agent_peer_token"
                        or previous_name != "agent_peer_token"
                        or previous_link != link_id
                    ):
                        raise InventoryError(
                            f"{prefix} reuses secret material from {previous_label}"
                        )
                else:
                    secret_digests[digest] = (
                        link_id,
                        secret_name,
                        f"{unit_id}/{secret_name}",
                    )
            if len(set(unit_secret_digests.values())) != len(unit_secret_digests):
                raise InventoryError(f"{prefix} uses the same bytes for different secret purposes")
            for private_name in TLS_PRIVATE_FILES:
                content = _validate_material_file(
                    material_dir / "tls" / private_name,
                    f"{prefix} {private_name}",
                )
                digest = hashlib.sha256(content).hexdigest()
                if digest in tls_key_digests:
                    raise InventoryError(
                        f"{prefix} reuses a TLS private key from {tls_key_digests[digest]}"
                    )
                tls_key_digests[digest] = f"{unit_id}/{private_name}"
            for tls_name in TLS_FILES:
                path = material_dir / "tls" / tls_name
                if path.is_symlink():
                    raise InventoryError(f"{prefix} TLS file must not be a symbolic link: {path}")
                if not path.is_file():
                    raise InventoryError(f"{prefix} TLS file is missing: {path}")

        if management_ip != metrics_bind and not ipaddress.ip_address(metrics_bind).is_loopback:
            raise InventoryError(f"{prefix}.metrics_bind_address must be loopback or management_ip")
        if agent_bind not in {"127.0.0.1", "::1", management_ip}:
            raise InventoryError(f"{prefix}.agent_bind_address must be loopback or management_ip")

    inventory["_validated_site_id"] = site_id
    return inventory


def _env_assignment(name: str, value: Any) -> str:
    return f"{name}={shlex.quote(str(value))}"


def _env_lines(inventory: dict[str, Any], unit: dict[str, Any]) -> list[str]:
    release = inventory["release"]
    registry = inventory["registry"]
    metrics = unit["metrics_ports"]
    return [
        _env_assignment("RI_IMAGE", release["image"]),
        _env_assignment("RI_VERIFICATION_MODE", unit["verification_mode"]),
        _env_assignment("RI_AGENT_SERVER_ID", unit["agent_server_id"]),
        _env_assignment("RI_AGENT_KEY_ID", unit["agent_key_id"]),
        _env_assignment("RI_TRACE_PRODUCER_UID", unit["trace_producer_uid"]),
        _env_assignment("RI_TRACE_PRODUCER_GID", unit["trace_producer_gid"]),
        _env_assignment("RI_TRACE_SOCKET_HOST_DIR", unit["trace_socket_host_dir"]),
        "RI_TRACE_RETENTION_SECONDS=3600",
        "RI_TRACE_SPOOL_MAX_EVENTS=1000000",
        "RI_AGENT_MAX_CONCURRENT_REQUESTS=512",
        "RI_AGENT_MAX_REQUEST_BODY_BYTES=4194304",
        "",
        _env_assignment("RI_WEB3_RPC_URL", registry["rpc_url"]),
        _env_assignment("RI_WEB3_CHAIN_ID", registry["chain_id"]),
        _env_assignment(
            "RI_REGISTRY_CONTRACT_ADDRESS", registry["contract_address"]
        ),
        _env_assignment("RI_REGISTRY_CODE_HASH", registry["runtime_code_hash"]),
        "RI_REGISTRY_POLL_INTERVAL_MS=2000",
        _env_assignment(
            "RI_REGISTRY_FALLBACK_CONFIRMATIONS",
            registry["fallback_confirmations"],
        ),
        _env_assignment(
            "RI_REGISTRY_MAX_STALENESS_SECONDS",
            registry["max_staleness_seconds"],
        ),
        "RI_RPC_MAX_RESPONSE_BYTES=4194304",
        "",
        _env_assignment("RI_WRAPPER_UPSTREAMS", ",".join(unit["resolver_upstreams"])),
        "RI_WRAPPER_UPSTREAM_TIMEOUT_MS=2000",
        "RI_WRAPPER_AGENT_TIMEOUT_MS=1000",
        "RI_WRAPPER_MAX_INFLIGHT=512",
        "RI_WRAPPER_MAX_TCP_CONNECTIONS=1024",
        "RI_WRAPPER_TCP_IO_TIMEOUT_MS=5000",
        "RI_WRAPPER_TRANSACTION_ID_REUSE_DELAY_MS=15000",
        "RI_WRAPPER_MAX_AGENT_RESPONSE_BYTES=4194304",
        _env_assignment("DNS_BIND_ADDRESS", unit["wrapper_ip"]),
        _env_assignment("DNS_PORT", unit["dns_port"]),
        _env_assignment("AGENT_BIND_ADDRESS", unit["agent_bind_address"]),
        _env_assignment("AGENT_PORT", unit["agent_port"]),
        _env_assignment("METRICS_BIND_ADDRESS", unit["metrics_bind_address"]),
        _env_assignment("METRICS_PORT", metrics["wrapper"]),
        _env_assignment(
            "REGISTRY_METRICS_BIND_ADDRESS", unit["metrics_bind_address"]
        ),
        _env_assignment("REGISTRY_METRICS_PORT", metrics["registry"]),
        _env_assignment(
            "TRACE_METRICS_BIND_ADDRESS", unit["metrics_bind_address"]
        ),
        _env_assignment("TRACE_METRICS_PORT", metrics["trace"]),
        "RI_DOCKER_LOG_MAX_SIZE=50m",
        "RI_DOCKER_LOG_MAX_FILES=5",
        "",
        _env_assignment("RI_FIELD_SITE_ID", inventory["site_id"]),
        _env_assignment("RI_FIELD_LINK_ID", unit["link_id"]),
        _env_assignment("RI_FIELD_UNIT_ID", unit["unit_id"]),
        _env_assignment("RI_FIELD_UNIT_ROLE", unit["role"]),
        _env_assignment("RI_FIELD_COMPOSE_PROJECT", unit["compose_project"]),
        _env_assignment("RI_FIELD_RELEASE_ROOT", unit["remote_release_root"]),
        _env_assignment("RI_FIELD_AGENT_SERVICE_URL", unit["_agent_service_url"]),
        _env_assignment(
            "RI_FIELD_AGENT_TLS_SERVER_NAME", unit["_agent_tls_server_name"]
        ),
        _env_assignment(
            "RI_FIELD_AGENT_SERVICE_PORT", unit["_agent_service_port"]
        ),
        _env_assignment("RI_FIELD_SHADOW_TEST_NAME", unit["shadow_test_name"]),
        _env_assignment("RI_FIELD_ROLLBACK_TARGET", unit["rollback_target"]),
    ]


def _copy_file(source: Path, target: Path, mode: int | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    if mode is not None:
        target.chmod(mode)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_hash_manifest(bundle: Path) -> None:
    files = sorted(
        path
        for path in bundle.rglob("*")
        if path.is_file() and path.relative_to(bundle).as_posix() != "metadata/SHA256SUMS"
    )
    lines = [f"{_file_sha256(path)}  {path.relative_to(bundle).as_posix()}" for path in files]
    target = bundle / "metadata/SHA256SUMS"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    target.chmod(0o600)


def render_bundles(inventory: dict[str, Any], output_root: Path, *, force: bool = False) -> list[Path]:
    site_root = (
        output_root.expanduser().resolve()
        / inventory["site_id"]
        / inventory["release"]["git_commit"][:12]
    )
    site_root.mkdir(parents=True, exist_ok=True)
    rendered: list[Path] = []
    for unit in inventory["units"]:
        bundle = site_root / unit["unit_id"]
        marker = bundle / ".ri-field-bundle"
        if bundle.exists() and any(bundle.iterdir()):
            if not force:
                raise InventoryError(f"bundle already exists: {bundle}")
            if not marker.is_file():
                raise InventoryError(f"refusing to replace an unmarked directory: {bundle}")
            shutil.rmtree(bundle)
        (bundle / "deploy/link/secrets").mkdir(parents=True)
        (bundle / "deploy/link/tls").mkdir(parents=True)
        (bundle / "metadata").mkdir(parents=True)
        (bundle / "scripts").mkdir(parents=True)
        marker.write_text("resolver-identity-field-bundle-v1\n", encoding="ascii")
        marker.chmod(0o600)

        _copy_file(COMPOSE_SOURCE, bundle / "deploy/link/docker-compose.yml", 0o444)
        _copy_file(
            Path(inventory["artifacts"]["identities_file"]),
            bundle / "deploy/link/identities-v2.json",
            0o444,
        )
        _copy_file(
            Path(inventory["artifacts"]["issuer_keys_file"]),
            bundle / "deploy/issuer-keys.json",
            0o444,
        )
        material_dir = Path(unit["private_material_dir"])
        for name in SECRET_FILES:
            _copy_file(material_dir / "secrets" / name, bundle / "deploy/link/secrets" / name, 0o400)
        for name in TLS_FILES:
            mode = 0o400 if name in TLS_PRIVATE_FILES else 0o444
            _copy_file(material_dir / "tls" / name, bundle / "deploy/link/tls" / name, mode)
        env_path = bundle / "deploy/link/.env"
        env_path.write_text("\n".join(_env_lines(inventory, unit)) + "\n", encoding="utf-8")
        env_path.chmod(0o600)

        for script_name in RUNTIME_SCRIPTS:
            _copy_file(
                REPO_ROOT / "scripts/field" / script_name,
                bundle / "scripts" / script_name,
                0o555,
            )
        _copy_file(
            REPO_ROOT / "scripts/field/lib/common.sh",
            bundle / "scripts/lib/common.sh",
            0o444,
        )

        rpc_host = urlsplit(inventory["registry"]["rpc_url"]).hostname
        metadata = {
            "schema_version": 1,
            "site_id": inventory["site_id"],
            "change_ticket": inventory["change_ticket"],
            "git_commit": inventory["release"]["git_commit"],
            "image": inventory["release"]["image"],
            "network_name": inventory["registry"]["network_name"],
            "chain_id": inventory["registry"]["chain_id"],
            "rpc_host": rpc_host,
            "contract_address": inventory["registry"]["contract_address"],
            "runtime_code_hash": inventory["registry"]["runtime_code_hash"],
            "link_id": unit["link_id"],
            "unit_id": unit["unit_id"],
            "unit_role": unit["role"],
            "hostname": unit["hostname"],
            "compose_project": unit["compose_project"],
            "agent_server_id": unit["agent_server_id"],
            "wrapper_ip": unit["wrapper_ip"],
            "dns_port": unit["dns_port"],
        }
        metadata_path = bundle / "metadata/unit.json"
        metadata_path.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        _write_hash_manifest(bundle)
        rendered.append(bundle)
    return rendered


def verify_bundle(bundle: Path) -> None:
    marker = bundle / ".ri-field-bundle"
    manifest = bundle / "metadata/SHA256SUMS"
    if not marker.is_file() or not manifest.is_file():
        raise InventoryError(f"not a field deployment bundle: {bundle}")
    if any(path.is_symlink() for path in bundle.rglob("*")):
        raise InventoryError("bundle must not contain symbolic links")
    expected: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise InventoryError(f"invalid SHA256SUMS line {line_number}")
        digest, relative = parts
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or relative in expected:
            raise InventoryError(f"unsafe SHA256SUMS path on line {line_number}")
        expected[relative] = digest
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and path.relative_to(bundle).as_posix() != "metadata/SHA256SUMS"
    }
    if actual_files != set(expected):
        raise InventoryError("bundle file set differs from SHA256SUMS")
    for relative, expected_digest in expected.items():
        if _file_sha256(bundle / relative) != expected_digest:
            raise InventoryError(f"bundle checksum mismatch: {relative}")
    env_text = (bundle / "deploy/link/.env").read_text(encoding="utf-8")
    if PLACEHOLDER_PATTERN.search(env_text):
        raise InventoryError("bundle environment contains a placeholder")
    if re.search(r"(?m)^RI_WEB3_CHAIN_ID=1$", env_text):
        raise InventoryError("bundle environment points to Ethereum Mainnet")
    for relative in (
        *(f"deploy/link/secrets/{name}" for name in SECRET_FILES),
        *(f"deploy/link/tls/{name}" for name in TLS_PRIVATE_FILES),
        "deploy/link/.env",
    ):
        mode = stat.S_IMODE((bundle / relative).stat().st_mode)
        if mode & 0o077:
            raise InventoryError(f"bundle private file permissions are too broad: {relative}")


def command_validate(args: argparse.Namespace) -> None:
    inventory = validate_inventory(
        load_json(args.inventory),
        template=args.template,
        check_materials=not args.skip_materials,
    )
    mode = "template" if args.template else "deployment"
    print(f"inventory valid ({mode}): {inventory.get('site_id', '<template>')}")


def command_render(args: argparse.Namespace) -> None:
    inventory = validate_inventory(load_json(args.inventory))
    bundles = render_bundles(inventory, args.output_root, force=args.force)
    for bundle in bundles:
        print(bundle)


def command_verify_bundle(args: argparse.Namespace) -> None:
    verify_bundle(args.bundle.resolve())
    print(f"bundle valid: {args.bundle.resolve()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate a site inventory")
    validate_parser.add_argument("--inventory", type=Path, required=True)
    validate_parser.add_argument("--template", action="store_true")
    validate_parser.add_argument(
        "--skip-materials",
        action="store_true",
        help="validate real values without opening identity or private material files",
    )
    validate_parser.set_defaults(func=command_validate)

    render_parser = subparsers.add_parser("render", help="render one private bundle per unit")
    render_parser.add_argument("--inventory", type=Path, required=True)
    render_parser.add_argument("--output-root", type=Path, required=True)
    render_parser.add_argument("--force", action="store_true")
    render_parser.set_defaults(func=command_render)

    verify_parser = subparsers.add_parser("verify-bundle", help="verify a rendered bundle")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser.set_defaults(func=command_verify_bundle)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except InventoryError as error:
        print(f"field deployment error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
