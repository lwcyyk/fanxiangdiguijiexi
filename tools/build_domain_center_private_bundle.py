#!/usr/bin/env python3
"""Build one root-only, host-bound private bundle from rendered deployment inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys


SCHEMA = "resolver-identity-domain-center-private-bundle-v1"
ROLES = ("management", "norn-a", "norn-b", "authdns", "r3", "r2", "r1")
REPO = Path(__file__).resolve().parents[1]
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class BundleError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise BundleError(f"{label} must be a regular non-symlink file: {path}")


def copy_secret_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise BundleError(f"secrets must be a real directory: {source}")
    destination.mkdir(mode=0o700)
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise BundleError(f"secret tree contains symlink: {path}")
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(mode=0o700)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, target)
            target.chmod(0o600)
        else:
            raise BundleError(f"secret tree contains unsupported object: {path}")


def add_role_support_files(role: str, staging: Path) -> None:
    source = REPO / "deploy" / "easy-install" / "product-kit" / role
    names: tuple[str, ...]
    if role in {"r1", "r2", "r3"}:
        names = ("kresd.conf",)
    elif role in {"norn-a", "norn-b"}:
        names = ("start-norn.sh", "start-read-proxy.sh", "nginx-readonly.conf")
    else:
        names = ()
    for name in names:
        path = source / name
        require_regular(path, f"role support file {name}")
        target = staging / name
        shutil.copyfile(path, target)
        target.chmod(0o600)


def build(
    output: Path,
    role: str,
    expected_host: str,
    compose_project: str,
    compose: Path | None,
    environment: Path,
    secrets: Path,
) -> Path:
    if role not in ROLES:
        raise BundleError(f"unsupported role: {role}")
    if HOST_RE.fullmatch(expected_host) is None:
        raise BundleError("expected_host is invalid")
    if PROJECT_RE.fullmatch(compose_project) is None:
        raise BundleError("compose_project is invalid")
    compose = compose or REPO / "deploy" / "domain-center" / role / "compose.yml"
    require_regular(compose, "compose")
    require_regular(environment, "environment")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.tmp-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(mode=0o700)
    try:
        compose_target = staging / "compose.yml"
        env_target = staging / "node.env"
        shutil.copyfile(compose, compose_target)
        shutil.copyfile(environment, env_target)
        compose_target.chmod(0o600)
        env_target.chmod(0o600)
        copy_secret_tree(secrets, staging / "secrets")
        add_role_support_files(role, staging)
        manifest = {
            "schema_version": SCHEMA,
            "role": role,
            "expected_host": expected_host,
            "compose_project": compose_project,
            "compose": {"path": compose_target.name, "sha256": sha256(compose_target)},
            "environment": {"path": env_target.name, "sha256": sha256(env_target)},
            "secrets": "secrets",
        }
        manifest_path = staging / "bundle.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_path.chmod(0o600)
        if output.exists():
            raise BundleError(f"output already exists: {output}")
        os.replace(staging, output)
        output.chmod(0o700)
        return output
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--compose", type=Path, help="defaults to deploy/domain-center/<role>/compose.yml")
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--secrets", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(
            args.output,
            args.role,
            args.expected_host,
            args.compose_project,
            args.compose,
            args.environment,
            args.secrets,
        )
        print(result)
        return 0
    except (BundleError, OSError, ValueError) as exc:
        print(f"private bundle error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
