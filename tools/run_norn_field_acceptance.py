#!/usr/bin/env python3
"""Run package-only Go-Norn field delivery acceptance in an ephemeral lab."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DELIVERY_MODULE = REPO_ROOT / "tools" / "manage_norn_field_delivery.py"
NORN_COMMIT = "a7be734ac2e829e2076d06d45719d2716abd3d72"
SCHEMA_HASH = "0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499"
REGISTRY_ADDRESS = "0x1000000000000000000000000000000000000001"
REGISTRY_KEY = "resolver-identity-registry-v2"
VERSION = "0.3.0-norn-knot-rc1"
SECOND_VERSION = "0.3.0-norn-knot-rc2"
THIRD_VERSION = "0.3.0-norn-knot-rc3"
REGISTRY_HELPER = (
    "registry:2.8.3@"
    "sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)


class AcceptanceError(RuntimeError):
    """Raised when a command-derived acceptance assertion fails."""


def _load_delivery_module() -> Any:
    spec = importlib.util.spec_from_file_location("manage_norn_field_delivery", DELIVERY_MODULE)
    if spec is None or spec.loader is None:
        raise AcceptanceError("cannot load field delivery module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


field = _load_delivery_module()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _free_port() -> int:
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def _json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(mode)
    temporary.replace(path)


class Lab:
    def __init__(
        self,
        *,
        keep_environment: bool,
        skip_full_tests: bool,
        trace_acceptance: Path,
    ) -> None:
        source_commit = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        self.source_commit = source_commit
        self.short_commit = source_commit[:8]
        self.prefix = f"ri-nfd-{self.short_commit}-{os.getpid()}"
        self.keep_environment = keep_environment
        self.skip_full_tests = skip_full_tests
        self.trace_acceptance = trace_acceptance.resolve()
        self.temp_root = Path(tempfile.mkdtemp(prefix=self.prefix + "-"))
        self.logs = self.temp_root / "logs"
        self.logs.mkdir()
        self.artifact_root = REPO_ROOT / "artifacts" / "field-deployment"
        self.release: Path | None = None
        self.registry_name = self.prefix + "-registry"
        self.registry_port = _free_port()
        self.registry_host = f"127.0.0.1:{self.registry_port}"
        self.field_network = self.prefix + "-field"
        self.commands: list[dict[str, Any]] = []
        self.positive: dict[str, str] = {}
        self.negative: dict[str, str] = {}
        self.lifecycle: dict[str, str] = {}
        self.package_roots: dict[str, Path] = {}
        self.install_roots: dict[str, Path] = {}
        self.image_refs: dict[str, str] = {}
        self.image_tags: dict[str, str] = {}
        self.local_image_tags: list[str] = []
        self.projects: dict[str, str] = {}
        self.node_runtime_env: dict[str, dict[str, str]] = {}
        self.resolver_runtime_env: dict[str, dict[str, str]] = {}
        self.bootstrap = ""
        self.inventory: dict[str, Any] = {}
        self.test_counts = {
            "rust_passed": 0,
            "rust_ignored": 0,
            "python_passed": 0,
            "foundry_passed": 0,
            "field_delivery_passed": 0,
        }
        self.cleaned = False

    def run(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path = REPO_ROOT,
        env: dict[str, str] | None = None,
        check: bool = True,
        record: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        log_path = self.logs / f"{len(self.commands):03d}-{name}.log"
        started = time.monotonic()
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        log_path.write_text(result.stdout, encoding="utf-8")
        if record:
            self.commands.append(
                {
                    "name": name,
                    "command": " ".join(command),
                    "exit_code": result.returncode,
                    "duration_ms": duration_ms,
                    "log_sha256": _sha256(log_path),
                }
            )
        if check and result.returncode != 0:
            tail = "\n".join(result.stdout.splitlines()[-30:])
            raise AcceptanceError(f"{name} failed with exit {result.returncode}:\n{tail}")
        return result

    def expect_failure(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path = REPO_ROOT,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = self.run(name, command, cwd=cwd, env=env, check=False)
        if result.returncode == 0:
            raise AcceptanceError(f"{name} unexpectedly succeeded")
        return result

    def preflight(self) -> None:
        status = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
            text=True,
        )
        if status:
            raise AcceptanceError("acceptance requires a clean committed worktree")
        branch = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "branch", "--show-current"],
            text=True,
        ).strip()
        if branch != "release/norn-knot-rc1":
            raise AcceptanceError(f"unexpected branch: {branch}")
        if not self.trace_acceptance.is_file():
            raise AcceptanceError("production Trace acceptance evidence is missing")
        for command in (
            "cargo",
            "docker",
            "forge",
            "git",
            "openssl",
            "python3",
            "sha256sum",
        ):
            if shutil.which(command) is None:
                raise AcceptanceError(f"required command is missing: {command}")
        self.run("docker-compose-version", ["docker", "compose", "version"])
        self.run(
            "ensure-clean-prefix",
            [
                "bash",
                "-c",
                f"! docker ps -a --format '{{{{.Names}}}}' | grep -F '{self.prefix}'",
            ],
        )

    @staticmethod
    def _rust_counts(output: str) -> tuple[int, int]:
        passed = 0
        ignored = 0
        for match in re.finditer(
            r"test result: ok\. ([0-9]+) passed; [0-9]+ failed; ([0-9]+) ignored",
            output,
        ):
            passed += int(match.group(1))
            ignored += int(match.group(2))
        return passed, ignored

    def run_test_gates(self) -> None:
        self.run(
            "rust-fmt",
            ["cargo", "fmt", "--all", "--check"],
            cwd=REPO_ROOT / "rust",
        )
        rust_test = self.run(
            "rust-test",
            ["cargo", "test", "--workspace", "--locked"],
            cwd=REPO_ROOT / "rust",
        )
        rust_passed, rust_ignored = self._rust_counts(rust_test.stdout)
        if rust_passed <= 0:
            raise AcceptanceError("could not derive Rust test count")
        self.test_counts["rust_passed"] = rust_passed
        self.test_counts["rust_ignored"] = rust_ignored
        self.run(
            "rust-clippy",
            [
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
            cwd=REPO_ROOT / "rust",
        )
        python_test = self.run(
            "python-test",
            ["python3", "-m", "pytest", "-q"],
        )
        python_match = re.search(r"([0-9]+) passed", python_test.stdout)
        if python_match is None:
            raise AcceptanceError("could not derive Python test count")
        self.test_counts["python_passed"] = int(python_match.group(1))
        field_collected = self.run(
            "field-delivery-test-collection",
            [
                "python3",
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "tests/unit/test_norn_field_delivery.py",
            ],
        )
        field_match = re.search(r"([0-9]+) tests collected", field_collected.stdout)
        if field_match is None:
            raise AcceptanceError("could not derive field delivery test count")
        self.test_counts["field_delivery_passed"] = int(field_match.group(1))
        self.run("forge-fmt", ["forge", "fmt", "--check"], cwd=REPO_ROOT / "contracts")
        self.run("forge-build", ["forge", "build"], cwd=REPO_ROOT / "contracts")
        forge_test = self.run(
            "forge-test",
            ["forge", "test", "-vvv"],
            cwd=REPO_ROOT / "contracts",
        )
        foundry_passed = sum(
            int(value)
            for value in re.findall(r"Suite result: ok\. ([0-9]+) passed", forge_test.stdout)
        )
        if foundry_passed <= 0:
            raise AcceptanceError("could not derive Foundry test count")
        self.test_counts["foundry_passed"] = foundry_passed
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            vendored = Path("/tmp/ri-tools/usr/bin/shellcheck")
            if not vendored.is_file():
                raise AcceptanceError("ShellCheck 0.9.0 is required")
            shellcheck = str(vendored)
        shell_scripts = sorted(
            str(path.relative_to(REPO_ROOT))
            for root in (
                REPO_ROOT / "deploy" / "field" / "common",
                REPO_ROOT / "deploy" / "field" / "management",
                REPO_ROOT / "deploy" / "field" / "norn-node",
                REPO_ROOT / "deploy" / "field" / "resolver-link",
                REPO_ROOT / "scripts" / "field-delivery",
            )
            for path in root.glob("*.sh")
        )
        self.run("shellcheck", [shellcheck, *shell_scripts])
        self.run(
            "inventory-template",
            [
                "python3",
                "tools/manage_norn_field_delivery.py",
                "validate",
                "--inventory",
                "deploy/field/inventory.example.yaml",
                "--template",
            ],
        )
        for adapter, env_file in (
            ("evm", ".env.example"),
            ("norn", ".env.norn.example"),
            ("external", ".env.external.example"),
        ):
            self.run(
                f"compose-link-{adapter}",
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(REPO_ROOT / "deploy" / "link" / env_file),
                    "-f",
                    str(REPO_ROOT / "deploy" / "link" / "docker-compose.yml"),
                    "config",
                    "--quiet",
                ],
            )
        for kind in field.PACKAGE_KINDS:
            self.run(
                f"compose-field-{kind}",
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(REPO_ROOT / "deploy" / "field" / kind / ".env.example"),
                    "-f",
                    str(REPO_ROOT / "deploy" / "field" / kind / "docker-compose.yml"),
                    "config",
                    "--quiet",
                ],
            )

    def _start_registry(self) -> None:
        self._ensure_image("registry-helper", REGISTRY_HELPER)
        self.run(
            "start-registry-helper",
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.registry_name,
                "--label",
                f"resolver-identity.acceptance={self.prefix}",
                "-p",
                f"127.0.0.1:{self.registry_port}:5000",
                REGISTRY_HELPER,
            ],
        )

    def _ensure_image(self, name: str, reference: str) -> None:
        inspected = self.run(
            f"inspect-{name}-image",
            ["docker", "image", "inspect", reference],
            check=False,
            record=False,
        )
        if inspected.returncode != 0:
            self.run(f"pull-{name}-image", ["docker", "pull", reference])

    def _push_image(self, key: str, local_tag: str) -> None:
        repository = f"{self.registry_host}/resolver-identity/{key}"
        pushed_tag = f"{repository}:{self.short_commit}"
        self.run(f"tag-{key}", ["docker", "tag", local_tag, pushed_tag])
        self.run(f"push-{key}", ["docker", "push", pushed_tag])
        inspected = self.run(
            f"inspect-{key}-digest",
            ["docker", "image", "inspect", pushed_tag, "--format", "{{json .RepoDigests}}"],
        )
        digests = json.loads(inspected.stdout.strip())
        reference = next(
            (value for value in digests if value.startswith(repository + "@sha256:")),
            None,
        )
        if reference is None:
            raise AcceptanceError(f"{key} image has no repository digest")
        self.image_tags[key] = pushed_tag
        self.image_refs[key] = reference

    def build_images(self) -> None:
        self._start_registry()
        local_tags = {
            "rust": f"{self.prefix}-rust:acceptance",
            "management": f"{self.prefix}-management:acceptance",
            "knot": f"{self.prefix}-knot:acceptance",
            "norn": f"{self.prefix}-norn:acceptance",
        }
        self.local_image_tags = list(local_tags.values())
        self.run(
            "build-rust-image",
            [
                "docker",
                "build",
                "--file",
                "docker/Dockerfile.rust",
                "--tag",
                local_tags["rust"],
                ".",
            ],
        )
        self.run(
            "build-management-image",
            [
                "docker",
                "build",
                "--file",
                "docker/Dockerfile.management",
                "--tag",
                local_tags["management"],
                ".",
            ],
        )
        self.run(
            "build-knot-image",
            [
                "docker",
                "build",
                "--file",
                "docker/Dockerfile.knot-trace",
                "--tag",
                local_tags["knot"],
                ".",
            ],
        )
        self.run(
            "build-norn-image",
            [
                "docker",
                "build",
                "--file",
                "deploy/norn-local/Dockerfile",
                "--build-arg",
                f"NORN_COMMIT={NORN_COMMIT}",
                "--tag",
                local_tags["norn"],
                "deploy/norn-local",
            ],
        )
        nginx_source = (
            "nginx:1.27.5-bookworm@"
            "sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d"
        )
        self._ensure_image("nginx", nginx_source)
        local_tags["nginx"] = f"{self.prefix}-nginx:acceptance"
        self.local_image_tags.append(local_tags["nginx"])
        self.run("tag-nginx-local", ["docker", "tag", nginx_source, local_tags["nginx"]])
        for key in field.IMAGE_KEYS:
            self._push_image(key, local_tags[key])
        revision = self.run(
            "verify-norn-revision",
            [
                "docker",
                "image",
                "inspect",
                self.image_refs["norn"],
                "--format",
                '{{index .Config.Labels "org.opencontainers.image.revision"}}',
            ],
        ).stdout.strip()
        if revision != NORN_COMMIT:
            raise AcceptanceError(f"Go-Norn revision mismatch: {revision}")
        for key, expected_user in (
            ("rust", "resolver-rust"),
            ("management", "resolver"),
            ("knot", "10003:10003"),
        ):
            actual_user = self.run(
                f"verify-{key}-user",
                [
                    "docker",
                    "image",
                    "inspect",
                    self.image_refs[key],
                    "--format",
                    "{{.Config.User}}",
                ],
            ).stdout.strip()
            if actual_user != expected_user:
                raise AcceptanceError(f"{key} image user is {actual_user}")
        knot_version = self.run(
            "verify-knot-version",
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/usr/sbin/kresd",
                self.image_refs["knot"],
                "-V",
            ],
        ).stdout
        if "Knot Resolver, version 6.3.0" not in knot_version:
            raise AcceptanceError("Knot Resolver image version is not pinned to 6.3.0")
        self.run(
            "verify-knot-trace-hook",
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                self.image_refs["knot"],
                "-c",
                "grep -a -q RI_KNOT_TRACE_HOOK_SOCKET /usr/sbin/kresd",
            ],
        )

    def _inventory(self) -> dict[str, Any]:
        inventory = field.load_inventory(REPO_ROOT / "deploy" / "field" / "inventory.example.yaml")
        inventory["release"]["version"] = VERSION
        inventory["release"]["git_commit"] = self.source_commit
        inventory["release"]["images"] = dict(self.image_refs)
        inventory["management"].update(
            {
                "host": "ri-hub-mgmt-01",
                "data_dir": str(self.temp_root / "data" / "management"),
                "work_dir": str(self.temp_root / "management" / "work"),
                "secret_dir": str(self.temp_root / "management" / "secrets"),
                "norn_tls_dir": str(self.temp_root / "management" / "norn-tls"),
            }
        )
        inventory["norn"].update(
            {
                "genesis_hash": "0x" + "1" * 64,
                "confirmations": 3,
                "max_scan_blocks": 1000,
                "field_network": self.field_network,
            }
        )
        for index, node in enumerate(inventory["norn"]["nodes"]):
            suffix = "a" if node["role"] == "node-a" else "b"
            node.update(
                {
                    "host": f"norn-node-{suffix}",
                    "read_hostname": f"norn-read-{suffix}",
                    "native_loopback_port": 45555 + index,
                    "data_dir": str(self.temp_root / "data" / f"norn-node-{suffix}"),
                    "config_dir": str(self.temp_root / "norn" / suffix / "config"),
                    "tls_dir": str(self.temp_root / "norn" / suffix / "tls"),
                    "node_key_profile": f"acceptance-node-{suffix}-key",
                    "tls_profile": f"acceptance-node-{suffix}-tls",
                }
            )
        for index, resolver in enumerate(inventory["resolvers"], start=1):
            host = f"resolver-L01-r{index}"
            resolver.update(
                {
                    "host": host,
                    "server_id": f"field-acceptance/L01/r{index}",
                    "agent_key_id": f"agent-key-L01-r{index}",
                    "data_dir": str(self.temp_root / "data" / host),
                    "trace_socket": str(self.temp_root / "trace" / host),
                    "secret_dir": str(self.temp_root / "resolver" / host / "secrets"),
                    "agent_tls_dir": str(self.temp_root / "resolver" / host / "agent-tls"),
                    "norn_tls_dir": str(self.temp_root / "resolver" / host / "norn-tls"),
                    "secret_profile": f"{host}-unique-secrets",
                    "tls_profile": f"{host}-unique-tls",
                }
            )
            # Published ports are observability hooks, not simulated cross-server
            # traffic. Give every package instance a distinct loopback address so
            # the clean runner need not own the field inventory's production IPs.
            self.resolver_runtime_env[host] = {
                "RI_MANAGEMENT_BIND_ADDRESS": f"127.77.1.{index}",
                "RI_RESOLVER_BIND_ADDRESS": f"127.77.2.{index}",
                "DNS_BIND_ADDRESS": f"127.77.3.{index}",
            }
        return inventory

    def render_release(self) -> None:
        self.inventory = self._inventory()
        release = field.render(
            self.inventory,
            self.artifact_root,
            force=True,
            trace_acceptance=self.trace_acceptance,
        )
        field.verify_release(release)
        self.release = release
        for kind in field.PACKAGE_KINDS:
            archive = release / f"resolver-identity-{kind}-{VERSION}.tar.gz"
            destination = self.temp_root / "packages" / kind
            destination.mkdir(parents=True)
            with tarfile.open(archive, "r:gz") as handle:
                handle.extractall(destination, filter="data")
            roots = list(destination.iterdir())
            if len(roots) != 1:
                raise AcceptanceError(f"{kind} package has an invalid root")
            self.package_roots[kind] = roots[0]
        self.positive["three_checksums_verified_packages"] = "passed"
        self.positive["secret_free_package_scan"] = "passed"

    def _install_env(self, install_root: Path) -> dict[str, str]:
        return {
            **os.environ,
            "RI_INSTALL_ROOT": str(install_root),
            "RI_FIELD_SIMULATION": "true",
            "RI_FIELD_MIN_FREE_MB": "1",
        }

    def install_hosts(self) -> None:
        if self.release is None:
            raise AcceptanceError("release is not rendered")
        host_kinds = {
            self.inventory["management"]["host"]: "management",
            **{node["host"]: "norn-node" for node in self.inventory["norn"]["nodes"]},
            **{resolver["host"]: "resolver-link" for resolver in self.inventory["resolvers"]},
        }
        if len(host_kinds) != 6:
            raise AcceptanceError("simulation must contain six distinct servers")
        for host, kind in host_kinds.items():
            install_root = self.temp_root / "servers" / host / "opt" / "resolver-identity"
            self.install_roots[host] = install_root
            config = self.release / "hosts" / host / "config"
            command = [
                str(self.package_roots[kind] / "install.sh"),
                "--version",
                VERSION,
                "--config-dir",
                str(config),
            ]
            environment = self._install_env(install_root)
            self.run(f"install-{host}", command, env=environment)
            first = (install_root / "current").resolve()
            self.run(f"install-idempotent-{host}", command, env=environment)
            if (install_root / "current").resolve() != first:
                raise AcceptanceError(f"idempotent install changed {host}")
            self.projects[host] = f"ri-{host.lower()}" if host != "ri-hub-mgmt-01" else host
        self.lifecycle["idempotent_install_all_six_hosts"] = "passed"

    @staticmethod
    def _chmod_tree(path: Path, directory_mode: int = 0o755, file_mode: int = 0o444) -> None:
        for item in [path, *path.rglob("*")]:
            item.chmod(directory_mode if item.is_dir() else file_mode)

    def _generate_norn_config(self, node: dict[str, Any]) -> None:
        config = Path(node["config_dir"])
        data = Path(node["data_dir"])
        config.mkdir(parents=True, exist_ok=True)
        data.mkdir(parents=True, exist_ok=True)
        config.chmod(0o777)
        data.chmod(0o777)
        self.run(
            f"generate-{node['host']}-config",
            [
                "docker",
                "run",
                "--rm",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--volume",
                f"{config}:/config",
                "--workdir",
                "/config",
                self.image_refs["norn"],
                "/usr/local/bin/norn-generate",
            ],
        )
        generated = config / "config.yml"
        if not generated.is_file():
            raise AcceptanceError(f"{node['host']} did not generate config.yml")
        generated.chmod(0o400)

    def _openssl(self, name: str, arguments: list[str]) -> None:
        self.run(name, ["openssl", *arguments])

    def _create_ca(self, root: Path) -> tuple[Path, Path]:
        root.mkdir(parents=True)
        key = root / "ca.key"
        cert = root / "ca.crt"
        self._openssl(
            "generate-lab-ca-key",
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
        )
        self._openssl(
            "generate-lab-ca-certificate",
            [
                "req",
                "-x509",
                "-new",
                "-sha256",
                "-days",
                "2",
                "-key",
                str(key),
                "-subj",
                f"/CN={self.prefix}-ca",
                "-out",
                str(cert),
            ],
        )
        return key, cert

    def _certificate(
        self,
        ca_key: Path,
        ca_cert: Path,
        destination: Path,
        name: str,
        serial: int,
        *,
        server_names: list[str] | None = None,
        client: bool = False,
    ) -> tuple[Path, Path]:
        destination.mkdir(parents=True, exist_ok=True)
        key = destination / f"{name}.key"
        csr = destination / f"{name}.csr"
        cert = destination / f"{name}.crt"
        extension = destination / f"{name}.ext"
        self._openssl(
            f"generate-{name}-key",
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
        )
        self._openssl(
            f"generate-{name}-csr",
            [
                "req",
                "-new",
                "-sha256",
                "-key",
                str(key),
                "-subj",
                f"/CN={name}",
                "-out",
                str(csr),
            ],
        )
        lines = ["extendedKeyUsage=clientAuth" if client else "extendedKeyUsage=serverAuth"]
        if server_names:
            lines.append(
                "subjectAltName=" + ",".join(f"DNS:{value}" for value in server_names)
            )
        extension.write_text("\n".join(lines) + "\n", encoding="ascii")
        self._openssl(
            f"sign-{name}-certificate",
            [
                "x509",
                "-req",
                "-sha256",
                "-days",
                "2",
                "-in",
                str(csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                str(serial),
                "-extfile",
                str(extension),
                "-out",
                str(cert),
            ],
        )
        csr.unlink()
        extension.unlink()
        return key, cert

    def generate_runtime_material(self) -> None:
        for node in self.inventory["norn"]["nodes"]:
            self._generate_norn_config(node)
        ca_root = self.temp_root / "private" / "ca"
        ca_key, ca_cert = self._create_ca(ca_root)
        serial = 10
        for node in self.inventory["norn"]["nodes"]:
            tls_dir = Path(node["tls_dir"])
            server_key, server_cert = self._certificate(
                ca_key,
                ca_cert,
                tls_dir,
                f"{node['role']}-server",
                serial,
                server_names=[node["read_hostname"], "localhost"],
            )
            serial += 1
            shutil.copy2(server_key, tls_dir / "server.key")
            shutil.copy2(server_cert, tls_dir / "server.crt")
            shutil.copy2(ca_cert, tls_dir / "ca.crt")
            self._chmod_tree(tls_dir)
        client_destinations = [
            (
                self.inventory["management"]["norn_tls_dir"],
                "management-norn-read",
            ),
            *[
                (resolver["norn_tls_dir"], f"{resolver['host']}-norn-read")
                for resolver in self.inventory["resolvers"]
            ],
        ]
        for path, name in client_destinations:
            destination = Path(path)
            client_key, client_cert = self._certificate(
                ca_key,
                ca_cert,
                destination,
                name,
                serial,
                client=True,
            )
            serial += 1
            shutil.copy2(client_key, destination / "client.key")
            shutil.copy2(client_cert, destination / "client.crt")
            shutil.copy2(ca_cert, destination / "ca.crt")
            self._chmod_tree(destination)
        self._generate_identity_and_agent_material(ca_key, ca_cert, serial)
        ca_key.chmod(0o400)
        self.positive["fresh_mtls_material"] = "passed"

    def _ed25519_raw(self, destination: Path, name: str) -> tuple[str, str]:
        pem = destination / f"{name}.pem"
        private_der = destination / f"{name}.private.der"
        public_der = destination / f"{name}.public.der"
        self._openssl(
            f"generate-{name}",
            ["genpkey", "-algorithm", "ED25519", "-out", str(pem)],
        )
        self._openssl(
            f"export-{name}-private",
            ["pkey", "-in", str(pem), "-outform", "DER", "-out", str(private_der)],
        )
        self._openssl(
            f"export-{name}-public",
            [
                "pkey",
                "-in",
                str(pem),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_der),
            ],
        )
        private = base64.b64encode(private_der.read_bytes()[-32:]).decode("ascii")
        public = base64.b64encode(public_der.read_bytes()[-32:]).decode("ascii")
        private_der.unlink()
        public_der.unlink()
        pem.unlink()
        return private, public

    def _generate_identity_and_agent_material(
        self,
        ca_key: Path,
        ca_cert: Path,
        serial: int,
    ) -> None:
        work = Path(self.inventory["management"]["work_dir"])
        secrets = Path(self.inventory["management"]["secret_dir"])
        work.mkdir(parents=True)
        secrets.mkdir(parents=True)
        work.chmod(0o777)
        secrets.chmod(0o755)
        identity_private, identity_public = self._ed25519_raw(secrets, "identity-issuer")
        snapshot_private, snapshot_public = self._ed25519_raw(secrets, "snapshot-issuer")
        (secrets / "identity-issuer.key").write_text(identity_private + "\n", encoding="ascii")
        (secrets / "snapshot-issuer.key").write_text(snapshot_private + "\n", encoding="ascii")
        now = int(time.time())
        identities: list[dict[str, Any]] = []
        for index, resolver in enumerate(self.inventory["resolvers"], start=1):
            secret_dir = Path(resolver["secret_dir"])
            agent_tls = Path(resolver["agent_tls_dir"])
            secret_dir.mkdir(parents=True)
            agent_tls.mkdir(parents=True)
            agent_private, agent_public = self._ed25519_raw(
                secret_dir,
                f"agent-L01-r{index}",
            )
            (secret_dir / "agent_private_key").write_text(agent_private + "\n", encoding="ascii")
            for token_name in (
                "trace_ingest_token",
                "agent_wrapper_token",
                "agent_peer_token",
            ):
                token = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
                (secret_dir / token_name).write_text(token + "\n", encoding="ascii")
            server_key, server_cert = self._certificate(
                ca_key,
                ca_cert,
                agent_tls,
                f"agent-L01-r{index}",
                serial,
                server_names=["agent", resolver["host"]],
            )
            serial += 1
            agent_client_key, agent_client_cert = self._certificate(
                ca_key,
                ca_cert,
                agent_tls,
                f"agent-client-L01-r{index}",
                serial,
                client=True,
            )
            serial += 1
            trace_key, trace_cert = self._certificate(
                ca_key,
                ca_cert,
                agent_tls,
                f"trace-client-L01-r{index}",
                serial,
                client=True,
            )
            serial += 1
            wrapper_key, wrapper_cert = self._certificate(
                ca_key,
                ca_cert,
                agent_tls,
                f"wrapper-client-L01-r{index}",
                serial,
                client=True,
            )
            serial += 1
            material = {
                "agent.key": server_key,
                "agent.crt": server_cert,
                "agent-client.key": agent_client_key,
                "agent-client.crt": agent_client_cert,
                "trace-client.key": trace_key,
                "trace-client.crt": trace_cert,
                "wrapper-client.key": wrapper_key,
                "wrapper-client.crt": wrapper_cert,
            }
            for target, source in material.items():
                shutil.copy2(source, agent_tls / target)
            shutil.copy2(ca_cert, agent_tls / "client-ca.crt")
            shutil.copy2(ca_cert, agent_tls / "agent-ca.crt")
            self._chmod_tree(secret_dir)
            self._chmod_tree(agent_tls)
            identities.append(
                {
                    "schema_version": "dns-server-identity-v2",
                    "server_id": resolver["server_id"],
                    "operator_id": "field-acceptance",
                    "role": "RECURSIVE" if index == 1 else "FORWARDER",
                    "endpoints": [
                        {
                            "ip": resolver["resolver_ip"],
                            "port": 53,
                            "transport": "udp",
                        },
                        {
                            "ip": resolver["resolver_ip"],
                            "port": 53,
                            "transport": "tcp",
                        },
                    ],
                    "anycast": False,
                    "agent": {
                        "key_id": resolver["agent_key_id"],
                        "algorithm": "ed25519",
                        "public_key": agent_public,
                        "service_url": f"https://{resolver['host']}:8443",
                    },
                    "valid_from": now - 60,
                    "valid_until": now + 86400,
                    "object_version": 1,
                    "status": "ACTIVE",
                    "issuer": "field-identity-authority",
                    "key_id": "identity-key-1",
                }
            )
        _write_json(work / "identities-v2.unsigned.json", {"identities": identities})
        _write_json(
            work / "issuer-keys.json",
            {
                "keys": [
                    {
                        "issuer": "field-identity-authority",
                        "key_id": "identity-key-1",
                        "algorithm": "ed25519",
                        "public_key": identity_public,
                    },
                    {
                        "issuer": "norn-registry",
                        "key_id": "snapshot-key-1",
                        "algorithm": "ed25519",
                        "public_key": snapshot_public,
                    },
                ]
            },
        )

    def _node_compose(
        self,
        host: str,
        *arguments: str,
        overrides: dict[str, str] | None = None,
        check: bool = True,
        name: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        root = self.install_roots[host] / "current"
        config = root / "config" / ".env"
        env = {
            **os.environ,
            "RI_NORN_UID": str(os.getuid()),
            "RI_NORN_GID": str(os.getgid()),
            **self.node_runtime_env[host],
            **(overrides or {}),
        }
        return self.run(
            name or f"compose-{host}-{arguments[-1]}",
            [
                "docker",
                "compose",
                "--project-name",
                f"ri-{host}",
                "--env-file",
                str(config),
                "-f",
                str(root / "docker-compose.yml"),
                *arguments,
            ],
            env=env,
            check=check,
        )

    def _management_command(
        self,
        name: str,
        script: str,
        arguments: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        record: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        root = self.install_roots["ri-hub-mgmt-01"] / "current"
        return self.run(
            name,
            [str(root / script), *arguments],
            env={**os.environ, **(env or {})},
            check=check,
            record=record,
        )

    def _wait_for(self, label: str, callback: Any, timeout: int = 120) -> Any:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                value = callback()
                if value:
                    return value
            except (AcceptanceError, json.JSONDecodeError, OSError) as error:
                last_error = error
            time.sleep(1)
        raise AcceptanceError(f"timed out waiting for {label}: {last_error}")

    @staticmethod
    def _peer_id_from_logs(logs: str) -> str | None:
        matches = re.findall(
            r'Node address: [^"]*/p2p/([^"\s]+)',
            logs,
        )
        return matches[-1] if matches else None

    def start_norn(self) -> tuple[str, str, str]:
        self.run("create-field-network", ["docker", "network", "create", self.field_network])
        node_a, node_b = self.inventory["norn"]["nodes"]
        self.node_runtime_env = {
            node_a["host"]: {
                "RI_NORN_P2P_BIND_ADDRESS": "127.77.0.11",
                "RI_NORN_READ_BIND_ADDRESS": "127.0.0.1",
                "RI_NORN_READ_PORT": "46555",
            },
            node_b["host"]: {
                "RI_NORN_P2P_BIND_ADDRESS": "127.77.0.12",
                "RI_NORN_READ_BIND_ADDRESS": "127.0.0.1",
                "RI_NORN_READ_PORT": "46556",
            },
        }
        self._node_compose(
            node_a["host"],
            "up",
            "-d",
            "norn-node",
            name="start-norn-node-a",
        )

        def peer_a() -> str | None:
            logs = self._node_compose(
                node_a["host"],
                "logs",
                "--no-color",
                "norn-node",
                name="probe-peer-a",
            ).stdout
            return self._peer_id_from_logs(logs)

        peer_id_a = self._wait_for("Node A peer ID", peer_a)
        self.bootstrap = f"/dns4/{node_a['host']}/tcp/31258/p2p/{peer_id_a}"
        self._node_compose(
            node_a["host"],
            "up",
            "-d",
            "norn-read-proxy",
            name="start-norn-read-a",
        )

        def genesis_a_ready() -> str | None:
            block = self._nornctl(
                "probe-genesis-a",
                "https://norn-read-a:8443",
                "block",
                "0",
                record=False,
            )
            return str(json.loads(block.stdout)["hash"])

        genesis_from_a = self._wait_for("Node A genesis", genesis_a_ready)
        self._node_compose(
            node_b["host"],
            "up",
            "-d",
            "norn-node",
            "norn-read-proxy",
            overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
            name="start-norn-node-b-and-read",
        )

        def peer_b() -> str | None:
            logs = self._node_compose(
                node_b["host"],
                "logs",
                "--no-color",
                "norn-node",
                overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
                name="probe-peer-b",
            ).stdout
            return self._peer_id_from_logs(logs)

        peer_id_b = self._wait_for("Node B peer ID", peer_b)
        if peer_id_a == peer_id_b:
            raise AcceptanceError("Node A and B have the same peer ID")

        def genesis_pair() -> tuple[str, str] | None:
            a = self._nornctl(
                "nornctl-genesis-a",
                "https://norn-read-a:8443",
                "block",
                "0",
                record=False,
            )
            b = self._nornctl(
                "nornctl-genesis-b",
                "https://norn-read-b:8443",
                "block",
                "0",
                record=False,
            )
            hash_a = json.loads(a.stdout)["hash"]
            hash_b = json.loads(b.stdout)["hash"]
            return (
                (hash_a, hash_b)
                if hash_a == hash_b == genesis_from_a
                else None
            )

        genesis_a, genesis_b = self._wait_for("matching Norn genesis", genesis_pair)
        self.inventory["norn"]["genesis_hash"] = genesis_a
        if self.release is None:
            raise AcceptanceError("release is not rendered")
        self.release = field.render(
            self.inventory,
            self.artifact_root,
            force=True,
            trace_acceptance=self.trace_acceptance,
        )
        for resolver in self.inventory["resolvers"]:
            rendered = self.release / "hosts" / resolver["host"] / "config" / ".env"
            installed = (
                self.install_roots[resolver["host"]]
                / "current"
                / "config"
                / ".env"
            )
            shutil.copy2(rendered, installed)
        self.positive["node_a_b_distinct_peer_ids"] = "passed"
        self.positive["node_a_b_independent_data_paths"] = "passed"
        self.positive["dual_node_genesis_agreement"] = "passed"
        self.positive["actual_genesis_synchronized_to_resolver_configs"] = "passed"
        return genesis_a, peer_id_a, peer_id_b

    def _nornctl(
        self,
        name: str,
        url: str,
        command: str,
        *arguments: str,
        check: bool = True,
        record: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._management_command(
            name,
            "nornctl.sh",
            [url, command, *arguments],
            check=check,
            record=record,
        )

    def prepare_snapshot(self, genesis: str) -> dict[str, Any]:
        work = Path(self.inventory["management"]["work_dir"])
        self._management_command(
            "sign-identities",
            "registry-tool.sh",
            [
                "sign",
                "--input",
                "/work/identities-v2.unsigned.json",
                "--private-key-file",
                "/run/field-secrets/identity-issuer.key",
                "--output",
                "/work/identities-v2.json",
            ],
        )
        self._management_command(
            "verify-identities",
            "registry-tool.sh",
            [
                "verify-identities",
                "--identities",
                "/work/identities-v2.json",
                "--issuer-keys",
                "/work/issuer-keys.json",
            ],
        )
        prepare = self._management_command(
            "prepare-registry-plan",
            "registry-tool.sh",
            [
                "prepare",
                "--identities",
                "/work/identities-v2.json",
                "--issuer-keys",
                "/work/issuer-keys.json",
                "--root-version",
                "1",
                "--chain-id",
                "20001",
                "--contract-address",
                REGISTRY_ADDRESS,
                "--contract-code-hash",
                SCHEMA_HASH,
                "--output",
                "/work/registry-plan-v2.json",
            ],
        )
        plan_result = json.loads(prepare.stdout.strip().splitlines()[-1])
        if plan_result["identity_count"] != 3:
            raise AcceptanceError("plan does not contain R1, R2 and R3")

        def common_checkpoint() -> tuple[int, str] | None:
            head_a = json.loads(
                self._nornctl(
                    "checkpoint-head-a",
                    "https://norn-read-a:8443",
                    "head",
                    record=False,
                ).stdout
            )["head"]
            head_b = json.loads(
                self._nornctl(
                    "checkpoint-head-b",
                    "https://norn-read-b:8443",
                    "head",
                    record=False,
                ).stdout
            )["head"]
            height = min(int(head_a), int(head_b))
            if height <= 0:
                return None
            block_a = json.loads(
                self._nornctl(
                    "checkpoint-block-a",
                    "https://norn-read-a:8443",
                    "block",
                    str(height),
                    record=False,
                ).stdout
            )
            block_b = json.loads(
                self._nornctl(
                    "checkpoint-block-b",
                    "https://norn-read-b:8443",
                    "block",
                    str(height),
                    record=False,
                ).stdout
            )
            if block_a["hash"] != block_b["hash"]:
                return None
            return height, str(block_a["hash"])

        checkpoint_height, checkpoint_hash = self._wait_for(
            "common signed checkpoint",
            common_checkpoint,
        )
        self._management_command(
            "prepare-norn-snapshot",
            "registry-tool.sh",
            [
                "prepare-norn-snapshot",
                "--plan",
                "/work/registry-plan-v2.json",
                "--expected-plan-hash",
                plan_result["plan_hash"],
                "--chain-id",
                "20001",
                "--genesis-block-hash",
                genesis,
                "--registry-address",
                REGISTRY_ADDRESS,
                "--registry-key",
                REGISTRY_KEY,
                "--snapshot-version",
                "1",
                "--checkpoint-height",
                str(checkpoint_height),
                "--checkpoint-hash",
                checkpoint_hash,
                "--valid-until",
                str(int(time.time()) + 86400),
                "--issuer",
                "norn-registry",
                "--key-id",
                "snapshot-key-1",
                "--private-key-file",
                "/run/field-secrets/snapshot-issuer.key",
                "--issuer-keys",
                "/work/issuer-keys.json",
                "--output",
                "/work/registry-snapshot-v1.json",
            ],
        )
        self._management_command(
            "verify-norn-snapshot",
            "registry-tool.sh",
            [
                "verify-norn-snapshot",
                "--snapshot",
                "/work/registry-snapshot-v1.json",
                "--issuer-keys",
                "/work/issuer-keys.json",
            ],
        )
        for resolver in self.inventory["resolvers"]:
            config = self.install_roots[resolver["host"]] / "current" / "config"
            shutil.copy2(work / "identities-v2.json", config / "identities-v2.json")
            shutil.copy2(work / "issuer-keys.json", config / "issuer-keys.json")
        self.positive["management_signed_three_identities"] = "passed"
        self.positive["management_signed_norn_snapshot"] = "passed"
        return {
            "plan_hash": plan_result["plan_hash"],
            "checkpoint_height": checkpoint_height,
            "checkpoint_hash": checkpoint_hash,
        }

    def publish_snapshot(self) -> str:
        work = Path(self.inventory["management"]["work_dir"])
        denied = self.run(
            "read-proxy-write-method-denied",
            [
                "docker",
                "run",
                "--rm",
                "--network",
                self.field_network,
                "--env",
                "NORN_PUBLISHER_TLS_CA_FILE=/tls/ca.crt",
                "--env",
                "NORN_PUBLISHER_TLS_CLIENT_CERT_FILE=/tls/client.crt",
                "--env",
                "NORN_PUBLISHER_TLS_CLIENT_KEY_FILE=/tls/client.key",
                "--volume",
                f"{self.inventory['management']['norn_tls_dir']}:/tls:ro",
                "--volume",
                f"{work / 'registry-snapshot-v1.json'}:/input/snapshot.json:ro",
                self.image_refs["norn"],
                "/usr/local/bin/norn-local-publisher",
                "norn-read-a:8443",
                REGISTRY_ADDRESS[2:],
                REGISTRY_KEY,
                "/input/snapshot.json",
            ],
            check=False,
        )
        if denied.returncode == 0:
            raise AcceptanceError("mTLS read proxy accepted a Norn write method")
        self.negative["mtls_read_proxy_write_method"] = "failed-closed"
        publish = self._management_command(
            "publish-snapshot-from-package",
            "publish-norn.sh",
            [
                str(work / "registry-snapshot-v1.json"),
                REGISTRY_ADDRESS,
                REGISTRY_KEY,
            ],
            env={"RI_FIELD_SIMULATION": "true"},
        )
        transaction = json.loads(publish.stdout.strip().splitlines()[-1])
        transaction_hash = str(transaction["transaction_hash"])
        if not re.fullmatch(r"[0-9a-f]{64}", transaction_hash):
            raise AcceptanceError("Norn publisher returned an invalid transaction hash")
        expected = _json_file(work / "registry-snapshot-v1.json")

        def both_nodes_read_snapshot() -> bool:
            for suffix in ("a", "b"):
                result = self._nornctl(
                    f"read-published-snapshot-{suffix}",
                    f"https://norn-read-{suffix}:8443",
                    "read",
                    REGISTRY_ADDRESS,
                    REGISTRY_KEY,
                    record=False,
                )
                if json.loads(result.stdout) != expected:
                    return False
            return True

        self._wait_for("snapshot on both Norn nodes", both_nodes_read_snapshot)
        baseline = min(
            int(
                json.loads(
                    self._nornctl(
                        "post-publish-head-a",
                        "https://norn-read-a:8443",
                        "head",
                        record=False,
                    ).stdout
                )["head"]
            ),
            int(
                json.loads(
                    self._nornctl(
                        "post-publish-head-b",
                        "https://norn-read-b:8443",
                        "head",
                        record=False,
                    ).stdout
                )["head"]
            ),
        )

        def confirmations_reached() -> bool:
            head_a = int(
                json.loads(
                    self._nornctl(
                        "confirm-head-a",
                        "https://norn-read-a:8443",
                        "head",
                        record=False,
                    ).stdout
                )["head"]
            )
            head_b = int(
                json.loads(
                    self._nornctl(
                        "confirm-head-b",
                        "https://norn-read-b:8443",
                        "head",
                        record=False,
                    ).stdout
                )["head"]
            )
            return min(head_a, head_b) >= baseline + int(self.inventory["norn"]["confirmations"])

        self._wait_for("snapshot confirmations", confirmations_reached)
        self.positive["package_publication_replicated_to_both_nodes"] = "passed"
        return transaction_hash

    def _resolver_compose(
        self,
        host: str,
        *arguments: str,
        env_overrides: dict[str, str] | None = None,
        check: bool = True,
        name: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        root = self.install_roots[host] / "current"
        return self.run(
            name or f"compose-{host}-{arguments[-1]}",
            [
                "docker",
                "compose",
                "--project-name",
                f"ri-{host.lower()}",
                "--env-file",
                str(root / "config" / ".env"),
                "-f",
                str(root / "docker-compose.yml"),
                *arguments,
            ],
            env={
                **os.environ,
                **self.resolver_runtime_env[host],
                **(env_overrides or {}),
            },
            check=check,
        )

    @staticmethod
    def _sqlite_state(database: Path) -> dict[str, Any]:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            snapshot = connection.execute(
                """
                SELECT adapter_type,chain_identity,registry_locator,
                       registry_schema_hash,finalized_block,finalized_block_hash,
                       snapshot_json
                  FROM ri_v2_registry_snapshot
                 ORDER BY snapshot_key
                """
            ).fetchall()
            meta = dict(
                connection.execute(
                    """
                    SELECT meta_key,meta_value FROM ri_v2_meta
                     WHERE meta_key IN ('registry_last_success_epoch','cache_generation')
                    """
                ).fetchall()
            )
            identities = int(
                connection.execute("SELECT COUNT(*) FROM ri_v2_identities").fetchone()[0]
            )
            legacy = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM ri_v2_registry_snapshot
                     WHERE chain_id != 0 OR contract_address != ''
                        OR contract_code_hash != ''
                    """
                ).fetchone()[0]
            )
        finally:
            connection.close()
        return {
            "integrity": integrity,
            "snapshot": snapshot,
            "meta": meta,
            "identity_count": identities,
            "legacy_evm_value_count": legacy,
        }

    def sync_resolvers(self) -> dict[str, Any]:
        checkpoints: dict[str, Any] = {}
        database_paths: list[str] = []
        inodes: list[int] = []
        for resolver in self.inventory["resolvers"]:
            data = Path(resolver["data_dir"])
            data.mkdir(parents=True, exist_ok=True)
            data.chmod(0o777)
            self._resolver_compose(
                resolver["host"],
                "run",
                "--rm",
                "--no-deps",
                "registry-sync",
                env_overrides={"RI_REGISTRY_SYNC_ONCE": "true"},
                name=f"sync-{resolver['host']}",
            )
            database = data / "evidence-v2.db"
            state = self._sqlite_state(database)
            if (
                state["integrity"] != "ok"
                or state["identity_count"] != 3
                or state["legacy_evm_value_count"] != 0
            ):
                raise AcceptanceError(f"invalid SQLite snapshot on {resolver['host']}: {state}")
            rows = state["snapshot"]
            anchors = {
                (row[0], row[1], row[2], row[3], row[4], row[5]) for row in rows
            }
            if len(anchors) != 1:
                raise AcceptanceError(f"{resolver['host']} does not have one chain anchor")
            anchor = next(iter(anchors))
            checkpoints[resolver["host"]] = {
                "database": f"{resolver['host']}/evidence-v2.db",
                "database_path_sha256": hashlib.sha256(
                    str(database.resolve()).encode()
                ).hexdigest(),
                "checkpoint_height": anchor[4],
                "checkpoint_hash": anchor[5],
                "identity_count": state["identity_count"],
                "integrity": state["integrity"],
            }
            database_paths.append(str(database.resolve()))
            inodes.append(database.stat().st_ino)
        if len(set(database_paths)) != 3 or len(set(inodes)) != 3:
            raise AcceptanceError("R1, R2 and R3 do not use independent SQLite files")
        state_roots = {
            json.loads(row[6])["state_root"]
            for resolver in self.inventory["resolvers"]
            for row in self._sqlite_state(
                Path(resolver["data_dir"]) / "evidence-v2.db"
            )["snapshot"]
        }
        if len(state_roots) != 1:
            raise AcceptanceError("resolver Registry Sync state roots disagree")
        self.positive["three_independent_sqlite_snapshots"] = "passed"
        self.positive["three_registry_sync_state_roots_agree"] = "passed"
        self.positive["non_evm_legacy_columns_empty"] = "passed"
        return checkpoints

    def start_agents_and_check_boundaries(self) -> None:
        for resolver in self.inventory["resolvers"]:
            host = resolver["host"]
            self._resolver_compose(
                host,
                "up",
                "-d",
                "--no-deps",
                "agent",
                name=f"start-agent-{host}",
            )
            container = self._resolver_compose(
                host,
                "ps",
                "-q",
                "agent",
                name=f"inspect-agent-id-{host}",
            ).stdout.strip()
            if not container:
                raise AcceptanceError(f"Agent did not start on {host}")
            inspect = json.loads(
                self.run(
                    f"inspect-agent-{host}",
                    ["docker", "inspect", container],
                ).stdout
            )[0]
            environment = inspect["Config"]["Env"]
            networks = set(inspect["NetworkSettings"]["Networks"])
            if any(
                value.startswith(("RI_CHAIN_RPC", "RI_NORN_")) for value in environment
            ):
                raise AcceptanceError(f"Agent on {host} received Norn adapter configuration")
            if any(name.endswith("registry-egress") for name in networks):
                raise AcceptanceError(f"Agent on {host} joined Registry egress")
            if not any(
                mount["Source"] == resolver["data_dir"]
                and mount["Destination"] == "/var/lib/resolver-identity"
                for mount in inspect["Mounts"]
            ):
                raise AcceptanceError(f"Agent on {host} does not mount its local SQLite data")
            wrapper_id = self._resolver_compose(
                host,
                "ps",
                "-q",
                "wrapper",
                name=f"inspect-wrapper-id-{host}",
            ).stdout.strip()
            if resolver["role"] == "upstream" and wrapper_id:
                raise AcceptanceError(f"upstream {host} started Wrapper")
        self.positive["agents_read_local_sqlite_only"] = "passed"
        self.positive["upstream_wrapper_absent"] = "passed"
        self.positive["agent_wrapper_no_direct_norn_access"] = "passed"

    def _assert_failed_sync_preserves(
        self,
        name: str,
        resolver: dict[str, Any],
    ) -> None:
        database = Path(resolver["data_dir"]) / "evidence-v2.db"
        before = self._sqlite_state(database)
        result = self._resolver_compose(
            resolver["host"],
            "run",
            "--rm",
            "--no-deps",
            "registry-sync",
            env_overrides={"RI_REGISTRY_SYNC_ONCE": "true"},
            check=False,
            name=name,
        )
        if result.returncode == 0:
            raise AcceptanceError(f"{name} unexpectedly synchronized")
        after = self._sqlite_state(database)
        if before != after:
            raise AcceptanceError(f"{name} changed SQLite, heartbeat or generation")

    def run_negative_runtime_tests(self) -> None:
        node_a, node_b = self.inventory["norn"]["nodes"]
        resolver = self.inventory["resolvers"][0]
        self._node_compose(
            node_b["host"],
            "stop",
            "norn-read-proxy",
            overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
            name="stop-norn-read-b",
        )
        self._assert_failed_sync_preserves("single-node-failure-sync", resolver)
        self.negative["single_norn_node_unavailable"] = "failed-closed"
        self.negative["failed_sync_preserved_sqlite_heartbeat_generation"] = "failed-closed"
        self._node_compose(
            node_b["host"],
            "up",
            "-d",
            "norn-read-proxy",
            overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
            name="restart-norn-read-b",
        )
        self._wait_for(
            "Node B read proxy recovery",
            lambda: self._nornctl(
                "probe-read-b-recovery",
                "https://norn-read-b:8443",
                "head",
                record=False,
            ).returncode
            == 0,
        )

        self._node_compose(
            node_b["host"],
            "down",
            "--remove-orphans",
            overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
            name="stop-node-b-for-disagreement",
        )
        data = Path(node_b["data_dir"])
        preserved = data.with_name(data.name + ".preserved")
        data.rename(preserved)
        data.mkdir()
        data.chmod(0o777)
        try:
            self._node_compose(
                node_b["host"],
                "up",
                "-d",
                "norn-node",
                "norn-read-proxy",
                overrides={"RI_NORN_ROLE": "node-a", "RI_NORN_BOOTSTRAP": ""},
                name="start-isolated-node-b-chain",
            )
            self._wait_for(
                "isolated Node B",
                lambda: self._nornctl(
                    "probe-isolated-b",
                    "https://norn-read-b:8443",
                    "head",
                    record=False,
                ).returncode
                == 0,
            )
            self._assert_failed_sync_preserves("dual-node-disagreement-sync", resolver)
            self.negative["norn_a_b_checkpoint_disagreement"] = "failed-closed"
        finally:
            self._node_compose(
                node_b["host"],
                "down",
                "--remove-orphans",
                overrides={"RI_NORN_ROLE": "node-a", "RI_NORN_BOOTSTRAP": ""},
                check=False,
                name="stop-isolated-node-b-chain",
            )
            shutil.rmtree(data, ignore_errors=True)
            preserved.rename(data)
            self._node_compose(
                node_b["host"],
                "up",
                "-d",
                "norn-node",
                "norn-read-proxy",
                overrides={"RI_NORN_BOOTSTRAP": self.bootstrap},
                name="restore-node-b-chain",
            )
        self._wait_for(
            "restored Node B snapshot",
            lambda: json.loads(
                self._nornctl(
                    "read-restored-b",
                    "https://norn-read-b:8443",
                    "read",
                    REGISTRY_ADDRESS,
                    REGISTRY_KEY,
                    record=False,
                ).stdout
            )
            == _json_file(
                Path(self.inventory["management"]["work_dir"])
                / "registry-snapshot-v1.json"
            ),
        )

    def lifecycle_acceptance(self) -> None:
        if self.release is None:
            raise AcceptanceError("release is not rendered")
        versions: dict[str, tuple[Path, dict[str, Any]]] = {}
        for version in (SECOND_VERSION, THIRD_VERSION):
            inventory = copy.deepcopy(self.inventory)
            inventory["release"]["version"] = version
            release = field.render(
                inventory,
                self.temp_root / f"upgrade-artifacts-{version}",
                force=True,
                trace_acceptance=self.trace_acceptance,
            )
            package_paths: dict[str, Path] = {}
            for kind in field.PACKAGE_KINDS:
                archive = release / f"resolver-identity-{kind}-{version}.tar.gz"
                destination = self.temp_root / "upgrade-packages" / version / kind
                destination.mkdir(parents=True)
                with tarfile.open(archive, "r:gz") as handle:
                    handle.extractall(destination, filter="data")
                package_paths[kind] = next(destination.iterdir())
            versions[version] = (release, package_paths)
        host_kinds = {
            self.inventory["management"]["host"]: "management",
            **{node["host"]: "norn-node" for node in self.inventory["norn"]["nodes"]},
            **{resolver["host"]: "resolver-link" for resolver in self.inventory["resolvers"]},
        }
        release_two, packages_two = versions[SECOND_VERSION]
        for host, kind in host_kinds.items():
            env = self._install_env(self.install_roots[host])
            self.run(
                f"upgrade-{host}",
                [
                    str(packages_two[kind] / "upgrade.sh"),
                    "--version",
                    SECOND_VERSION,
                    "--config-dir",
                    str(release_two / "hosts" / host / "config"),
                ],
                env=env,
            )
            if (self.install_roots[host] / "current").resolve().name != SECOND_VERSION:
                raise AcceptanceError(f"{host} did not upgrade")
            self.run(
                f"rollback-{host}",
                [str(self.install_roots[host] / "current" / "rollback.sh")],
                env=env,
            )
            if (self.install_roots[host] / "current").resolve().name != VERSION:
                raise AcceptanceError(f"{host} did not rollback")
        self.lifecycle["upgrade_all_six_hosts"] = "passed"
        self.lifecycle["rollback_all_six_hosts"] = "passed"

        release_three, packages_three = versions[THIRD_VERSION]
        management = self.inventory["management"]["host"]
        failing_config = self.temp_root / "failing-config"
        shutil.copytree(release_three / "hosts" / management / "config", failing_config)
        with (failing_config / ".env").open("a", encoding="utf-8") as handle:
            handle.write("RI_FIELD_FORCE_HEALTH_FAILURE='true'\n")
        failure = self.run(
            "upgrade-health-failure-auto-rollback",
            [
                str(packages_three["management"] / "upgrade.sh"),
                "--version",
                THIRD_VERSION,
                "--config-dir",
                str(failing_config),
            ],
            env=self._install_env(self.install_roots[management]),
            check=False,
        )
        if failure.returncode == 0:
            raise AcceptanceError("forced upgrade health failure succeeded")
        if (self.install_roots[management] / "current").resolve().name != VERSION:
            raise AcceptanceError("health failure did not restore the old program symlink")
        self.lifecycle["health_failure_automatic_program_rollback"] = "passed"

    def uninstall_acceptance(self) -> None:
        data_paths = [
            Path(self.inventory["management"]["data_dir"]),
            *(Path(node["data_dir"]) for node in self.inventory["norn"]["nodes"]),
            *(Path(resolver["data_dir"]) for resolver in self.inventory["resolvers"]),
        ]
        for host, install_root in self.install_roots.items():
            self.run(
                f"ordinary-uninstall-{host}",
                [str(install_root / "current" / "uninstall.sh")],
                env=self._install_env(install_root),
            )
            if (install_root / "current").exists():
                raise AcceptanceError(f"ordinary uninstall retained current on {host}")
        if any(not path.exists() for path in data_paths):
            raise AcceptanceError("ordinary uninstall removed persistent data")
        self.lifecycle["ordinary_uninstall_preserved_data"] = "passed"

        purge_root = self.temp_root / "purge-test" / "install"
        purge_config = self.temp_root / "purge-test" / "config"
        if self.release is None:
            raise AcceptanceError("release is not rendered")
        shutil.copytree(
            self.release / "hosts" / "ri-hub-mgmt-01" / "config",
            purge_config,
        )
        purge_data = self.temp_root / "purge-test" / "owned-data"
        env_path = purge_config / ".env"
        env_text = env_path.read_text(encoding="utf-8")
        env_text = re.sub(
            r"^RI_FIELD_DATA_DIR=.*$",
            f"RI_FIELD_DATA_DIR='{purge_data}'",
            env_text,
            flags=re.MULTILINE,
        )
        env_path.write_text(env_text, encoding="utf-8")
        environment = self._install_env(purge_root)
        self.run(
            "install-purge-test",
            [
                str(self.package_roots["management"] / "install.sh"),
                "--version",
                VERSION,
                "--config-dir",
                str(purge_config),
            ],
            env=environment,
        )
        self.run(
            "explicit-purge-data",
            [str(purge_root / "current" / "uninstall.sh"), "--purge-data"],
            env=environment,
        )
        if purge_data.exists():
            raise AcceptanceError("--purge-data did not delete installer-owned data")
        self.lifecycle["explicit_purge_data"] = "passed"

    def stop_runtime(self) -> None:
        for resolver in self.inventory.get("resolvers", []):
            if resolver["host"] not in self.install_roots:
                continue
            self._resolver_compose(
                resolver["host"],
                "down",
                "--remove-orphans",
                check=False,
                name=f"stop-{resolver['host']}",
            )
        for node in self.inventory.get("norn", {}).get("nodes", []):
            if node["host"] not in self.install_roots:
                continue
            overrides = (
                {"RI_NORN_BOOTSTRAP": self.bootstrap}
                if node["role"] == "node-b" and self.bootstrap
                else None
            )
            self._node_compose(
                node["host"],
                "down",
                "--remove-orphans",
                overrides=overrides,
                check=False,
                name=f"stop-{node['host']}",
            )

    def secret_audit(self) -> dict[str, Any]:
        patterns = [
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?:gh[pousr]_[A-Za-z0-9]{30,})",
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            r"https?://[^/@\s]+:[^/@\s]+@",
        ]
        revisions = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-list", "HEAD"],
            text=True,
        ).splitlines()
        findings: list[str] = []
        for revision in revisions:
            for pattern in patterns:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(REPO_ROOT),
                        "grep",
                        "-I",
                        "-n",
                        "-E",
                        "-e",
                        pattern,
                        revision,
                        "--",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if result.returncode == 0:
                    findings.extend(result.stdout.splitlines())
            names = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "ls-tree", "-r", "--name-only", revision],
                text=True,
            ).splitlines()
            findings.extend(
                f"{revision}:{name}"
                for name in names
                if re.search(
                    r"(^|/)(\.env\.local|[^/]+\.(?:db|db-wal|db-shm|pem|p12|pfx|keystore|jks|key))$",
                    name,
                )
            )
        if findings:
            raise AcceptanceError(
                "high-confidence secret material exists in reachable Git history"
            )
        return {
            "result": "passed",
            "reachable_commits_scanned": len(revisions),
            "high_confidence_findings": 0,
        }

    def cleanup(self) -> None:
        try:
            if any(
                (root / "current").exists()
                for root in self.install_roots.values()
            ):
                self.stop_runtime()
        except Exception:
            pass
        subprocess.run(
            ["docker", "rm", "-f", self.registry_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["docker", "network", "rm", self.field_network],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        container_ids = subprocess.run(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=resolver-identity.acceptance={self.prefix}",
            ],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.split()
        if container_ids:
            subprocess.run(
                ["docker", "rm", "-f", *container_ids],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        for tag in [*self.image_tags.values(), *self.local_image_tags]:
            subprocess.run(
                ["docker", "image", "rm", tag],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        if not self.keep_environment:
            shutil.rmtree(self.temp_root, ignore_errors=True)
        remaining_containers = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"name={self.prefix}"],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.strip()
        remaining_network = subprocess.run(
            ["docker", "network", "ls", "-q", "--filter", f"name=^{self.field_network}$"],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.strip()
        self.cleaned = not remaining_containers and not remaining_network

    def write_acceptance(
        self,
        *,
        snapshot: dict[str, Any],
        transaction_hash: str,
        checkpoints: dict[str, Any],
        peer_ids: tuple[str, str],
        secret_audit: dict[str, Any],
    ) -> Path:
        if self.release is None:
            raise AcceptanceError("release is not rendered")
        manifest = _json_file(self.release / "release-manifest.json")
        packages = {
            item["kind"]: {
                "filename": item["filename"],
                "sha256": item["sha256"],
            }
            for item in manifest["packages"]
        }
        anchor = min(
            checkpoints.values(),
            key=lambda value: int(value["checkpoint_height"]),
        )
        checkpoint_heights = [
            int(value["checkpoint_height"]) for value in checkpoints.values()
        ]
        acceptance = {
            "schema_version": "resolver-identity-norn-field-acceptance-v1",
            "generated_at": _utc_now(),
            "branch": "release/norn-knot-rc1",
            "base_branch": "master",
            "source_commit": self.source_commit,
            "delivery_commit": self.source_commit,
            "go_norn_upstream_commit": NORN_COMMIT,
            "result": "passed",
            "release": {
                "version": VERSION,
                "packages": packages,
                "image_digests": self.image_refs,
                "production_trace_ready": manifest["production_trace_ready"],
                "field_package_ready": manifest["field_package_ready"],
                "real_server_deployed": manifest["real_server_deployed"],
                "production_traffic_enabled": manifest["production_traffic_enabled"],
                "p0_blockers": manifest["p0_blockers"],
            },
            "simulation": {
                "server_count": 6,
                "servers": [
                    "ri-hub-mgmt-01",
                    "norn-node-a",
                    "norn-node-b",
                    "resolver-L01-r1",
                    "resolver-L01-r2",
                    "resolver-L01-r3",
                ],
                "used_package_contents_only": True,
                "cross_server_localhost_used": False,
                "node_a_b_independent": True,
                "node_peer_id_sha256": [
                    hashlib.sha256(value.encode("utf-8")).hexdigest()
                    for value in peer_ids
                ],
                "resolver_sqlite_independent": True,
                "temporary_environment_cleaned": self.cleaned,
            },
            "registry": {
                "chain_id": 20001,
                "genesis_hash": self.inventory["norn"]["genesis_hash"],
                "registry_address": REGISTRY_ADDRESS,
                "registry_key": REGISTRY_KEY,
                "registry_schema_hash": SCHEMA_HASH,
                "plan_hash": snapshot["plan_hash"],
                "publication_transaction_hash": transaction_hash,
                "signed_checkpoint": {
                    "height": snapshot["checkpoint_height"],
                    "hash": snapshot["checkpoint_hash"],
                },
                "registry_sync_checkpoint": {
                    "height": anchor["checkpoint_height"],
                    "hash": anchor["checkpoint_hash"],
                    "recorded_from": "minimum per-resolver accepted checkpoint",
                    "height_range": [
                        min(checkpoint_heights),
                        max(checkpoint_heights),
                    ],
                },
            },
            "registry_sync": checkpoints,
            "boundaries": {
                "agents_read_local_sqlite_only": True,
                "agent_wrapper_direct_norn_access": False,
                "registry_sync_only_chain_client": True,
                "upstream_wrapper_started": False,
                "native_norn_grpc_externally_exposed": False,
                "read_proxy_write_methods_allowed": False,
            },
            "positive_tests": self.positive,
            "negative_tests": self.negative,
            "lifecycle_tests": self.lifecycle,
            "test_counts": self.test_counts,
            "test_commands": self.commands,
            "secret_audit": secret_audit,
            "secrets_found": False,
        }
        if (
            not self.cleaned
            or any(value != "passed" for value in self.positive.values())
            or any(value != "failed-closed" for value in self.negative.values())
            or any(value != "passed" for value in self.lifecycle.values())
        ):
            raise AcceptanceError("acceptance assertions are incomplete")
        destination = REPO_ROOT / "specs" / "norn-field-delivery" / "acceptance.json"
        _write_json(destination, acceptance)
        logs_destination = self.release / "acceptance-logs"
        if not logs_destination.exists() and self.logs.exists():
            shutil.copytree(self.logs, logs_destination)
        return destination

    def execute(self) -> Path:
        self.preflight()
        if not self.skip_full_tests:
            self.run_test_gates()
        self.build_images()
        self.render_release()
        self.install_hosts()
        self.generate_runtime_material()
        genesis, peer_a, peer_b = self.start_norn()
        snapshot = self.prepare_snapshot(genesis)
        transaction_hash = self.publish_snapshot()
        checkpoints = self.sync_resolvers()
        self.start_agents_and_check_boundaries()
        self.run_negative_runtime_tests()
        self.lifecycle_acceptance()
        self.stop_runtime()
        self.uninstall_acceptance()
        audit = self.secret_audit()
        self.cleanup()
        return self.write_acceptance(
            snapshot=snapshot,
            transaction_hash=transaction_hash,
            checkpoints=checkpoints,
            peer_ids=(peer_a, peer_b),
            secret_audit=audit,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-environment",
        action="store_true",
        help="retain the temporary directory for debugging; containers are still stopped",
    )
    parser.add_argument(
        "--skip-full-tests",
        action="store_true",
        help="debug only: omit language test gates (never use for final evidence)",
    )
    parser.add_argument(
        "--trace-acceptance",
        type=Path,
        required=True,
        help="script-generated Knot Trace acceptance for this source commit",
    )
    args = parser.parse_args()
    lab = Lab(
        keep_environment=args.keep_environment,
        skip_full_tests=args.skip_full_tests,
        trace_acceptance=args.trace_acceptance,
    )
    try:
        destination = lab.execute()
    except Exception as error:
        lab.cleanup()
        print(f"field acceptance failed: {error}", file=sys.stderr)
        if args.keep_environment:
            print(f"temporary directory: {lab.temp_root}", file=sys.stderr)
        return 1
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
