#!/usr/bin/env python3
"""Safely capture and adopt one existing domain-center Compose project without deleting state."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys


ROLES = ("management", "norn-a", "norn-b", "authdns", "r3", "r2", "r1")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
DB_NAMES = ("evidence-v2.db", "trace-spool.db")


class AdoptError(RuntimeError):
    pass


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        raise AdoptError(f"command failed: {' '.join(command[:4])}: {(result.stdout + result.stderr)[-2000:]}")
    return result


def compose(project: str, compose_file: Path, environment: Path, *arguments: str) -> list[str]:
    return [
        "docker", "compose", "--project-name", project,
        "--env-file", str(environment), "-f", str(compose_file), *arguments,
    ]


def container_ids(project: str) -> list[str]:
    result = run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}}"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def inspect_containers(project: str) -> list[dict[str, object]]:
    ids = container_ids(project)
    if not ids:
        raise AdoptError(f"no existing containers found for Compose project {project}")
    result = run(["docker", "inspect", *ids])
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise AdoptError("docker inspect did not return an array")
    records = []
    for item in value:
        if not isinstance(item, dict):
            raise AdoptError("docker inspect returned a non-object")
        config = item.get("Config", {})
        labels = config.get("Labels", {}) if isinstance(config, dict) else {}
        state = item.get("State", {})
        host = item.get("HostConfig", {})
        records.append({
            "id": item.get("Id"),
            "name": str(item.get("Name", "")).lstrip("/"),
            "service": labels.get("com.docker.compose.service") if isinstance(labels, dict) else None,
            "image": item.get("Image"),
            "restart_count": item.get("RestartCount"),
            "running": state.get("Running") if isinstance(state, dict) else None,
            "mounts": item.get("Mounts", []),
            "ports": host.get("PortBindings", {}) if isinstance(host, dict) else {},
            "network_mode": host.get("NetworkMode") if isinstance(host, dict) else None,
            "networks": item.get("NetworkSettings", {}).get("Networks", {}) if isinstance(item.get("NetworkSettings"), dict) else {},
        })
    return records


def quick_check(data_dir: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    for name in DB_NAMES:
        path = data_dir / name
        if not path.exists():
            results[name] = "absent"
            continue
        if not path.is_file() or path.is_symlink():
            raise AdoptError(f"database path is unsafe: {path}")
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as database:
            row = database.execute("PRAGMA quick_check").fetchone()
        value = str(row[0]) if row else "no-result"
        if value.lower() != "ok":
            raise AdoptError(f"SQLite quick_check failed for {path}: {value}")
        results[name] = value
    return results


def service_set(records: list[dict[str, object]]) -> set[str]:
    return {str(record["service"]) for record in records if record.get("service")}


def mounts_equivalent(before: list[object], after: list[object]) -> bool:
    """Compare mounts, permitting removal of code-override binds under /usr/local/bin.

    The frozen service-level matrix replaces bind-mounted hotfix binaries with
    OCI-embedded binaries, so a removed /usr/local/bin bind is an accepted,
    evidence-recorded migration change. Persistent data/config/secret/tls/socket
    and cache mounts must match exactly.
    """
    if not isinstance(before, list) or not isinstance(after, list):
        return False

    def normalized(mounts: list[object]) -> set[tuple[str, str, str, str, bool]]:
        result: set[tuple[str, str, str, str, bool]] = set()
        for raw in mounts:
            if not isinstance(raw, dict):
                continue
            destination = str(raw.get("Destination", ""))
            if destination.startswith("/usr/local/bin/"):
                continue
            result.add((
                str(raw.get("Type", "")),
                str(raw.get("Source", "")),
                destination,
                str(raw.get("Mode", "")),
                bool(raw.get("RW")),
            ))
        return result

    return normalized(before) == normalized(after)


def wait_service(project: str, service: str, previous_restart_count: int) -> None:
    import time

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        records = inspect_containers(project)
        matching = [item for item in records if item.get("service") == service]
        if len(matching) == 1:
            item = matching[0]
            restart_count = item.get("restart_count")
            if item.get("running") is True and isinstance(restart_count, int) and restart_count <= previous_restart_count:
                time.sleep(2)
                check = [record for record in inspect_containers(project) if record.get("service") == service]
                if len(check) == 1 and check[0].get("running") is True and check[0].get("restart_count") == restart_count:
                    return
        time.sleep(1)
    raise AdoptError(f"service did not become stably running: {service}")


def capture(project: str, data_dir: Path) -> dict[str, object]:
    records = inspect_containers(project)
    return {
        "captured_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "project": project,
        "services": sorted(service_set(records)),
        "containers": records,
        "sqlite_quick_check": quick_check(data_dir),
    }


def adopt(args: argparse.Namespace) -> dict[str, object]:
    if args.role not in ROLES or PROJECT_RE.fullmatch(args.project) is None:
        raise AdoptError("invalid role or Compose project")
    if args.role == "management":
        raise AdoptError("management has no existing long-running cloud project to adopt")
    for path, label in ((args.compose, "compose"), (args.environment, "environment")):
        if not path.is_file() or path.is_symlink():
            raise AdoptError(f"{label} is not a regular file: {path}")
    before = capture(args.project, args.data_dir)
    rendered_services = {
        line.strip()
        for line in run(compose(args.project, args.compose, args.environment, "config", "--services")).stdout.splitlines()
        if line.strip()
    }
    if rendered_services != set(before["services"]):
        raise AdoptError(
            f"clean Compose service set differs from existing project: clean={sorted(rendered_services)} existing={before['services']}"
        )
    run(compose(args.project, args.compose, args.environment, "config", "--quiet"))
    ordered = {
        "authdns": ("registry-sync", "agent", "authority-proxy"),
        "r3": ("registry-sync", "agent", "trace-adapter", "trace-producer", "resolver"),
        "r2": ("registry-sync", "agent", "trace-adapter", "trace-producer", "resolver"),
        "r1": ("registry-sync", "agent", "trace-adapter", "trace-producer", "resolver", "wrapper"),
    }[args.role]
    if set(ordered) != rendered_services:
        raise AdoptError("role service order does not match rendered clean Compose")
    restart_counts = {
        str(item["service"]): int(item.get("restart_count", 0))
        for item in before["containers"]
        if item.get("service")
    }
    for service in ordered:
        run(compose(args.project, args.compose, args.environment, "up", "-d", "--pull", "never", "--no-deps", service))
        wait_service(args.project, service, restart_counts[service])
    after = capture(args.project, args.data_dir)
    if set(after["services"]) != rendered_services:
        raise AdoptError("post-adoption service set changed")
    before_by_service = {str(item["service"]): item for item in before["containers"]}
    before_sources = {
        str(mount.get("Source"))
        for item in before["containers"]
        for mount in item.get("mounts", [])
        if isinstance(mount, dict) and mount.get("Source")
    }
    for required in (args.data_dir,):
        resolved = str(required.resolve())
        if not any(source == resolved or source.startswith(resolved + "/") for source in before_sources):
            raise AdoptError(f"declared persistent path is not mounted by the existing project: {required}")
    for item in after["containers"]:
        service = str(item["service"])
        previous = before_by_service.get(service)
        if previous is None:
            raise AdoptError(f"unexpected post-adoption service: {service}")
        if not mounts_equivalent(previous.get("mounts"), item.get("mounts")) or item["ports"] != previous["ports"] or item["network_mode"] != previous["network_mode"]:
            raise AdoptError(
                "mount/port/network drift after adopting service "
                f"{service}: mounts={mounts_equivalent(previous.get('mounts'), item.get('mounts'))} "
                f"ports_before={previous.get('ports')} ports_after={item.get('ports')} "
                f"network_before={previous.get('network_mode')} network_after={item.get('network_mode')}"
            )
        if item.get("running") is not True:
            raise AdoptError(f"service is not running after adoption: {service}")
    hotfix_binds_removed: list[dict[str, str]] = []
    for service, previous in before_by_service.items():
        for raw in previous.get("mounts", []):
            if isinstance(raw, dict) and str(raw.get("Destination", "")).startswith("/usr/local/bin/"):
                hotfix_binds_removed.append({
                    "service": service,
                    "source": str(raw.get("Source", "")),
                    "destination": str(raw.get("Destination", "")),
                })
    evidence = {
        "schema_version": "resolver-identity-domain-center-adopt-existing-v1",
        "role": args.role,
        "project": args.project,
        "data_dir": str(args.data_dir.resolve()),
        "before": before,
        "after": after,
        "hotfix_binary_binds_removed": sorted(hotfix_binds_removed, key=lambda item: (item["service"], item["destination"])),
        "state_deleted": False,
        "cache_cleared": False,
        "volumes_removed": False,
        "result": "passed",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--project", required=True)
    parser.add_argument("--compose", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = adopt(args)
        print(json.dumps({"result": result["result"], "output": str(args.output)}, ensure_ascii=False))
        return 0
    except (AdoptError, OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"adopt-existing error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
