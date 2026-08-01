#!/usr/bin/env python3
"""Validate and collect evidence for the integrated Go-Norn + Knot RC."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
VERSION = "0.3.0-norn-knot-rc1"
EVIDENCE_ROOT = REPO / "specs" / "norn-knot-rc1"
ACCEPTANCE_PATHS = {
    "multichain": Path("specs/multichain-registry-adapter/acceptance.json"),
    "field": Path("specs/norn-field-delivery/acceptance.json"),
    "trace": Path("specs/production-resolver-trace/acceptance.json"),
}
GENERATED_PATHS = {
    *ACCEPTANCE_PATHS.values(),
    Path("specs/norn-knot-rc1/SHA256SUMS"),
    Path("specs/norn-knot-rc1/installation-order.md"),
    Path("specs/norn-knot-rc1/network-matrix.json"),
    Path("specs/norn-knot-rc1/offline-image-manifest.json"),
    Path("specs/norn-knot-rc1/release-manifest.json"),
    Path("specs/norn-knot-rc1/secret-requirements.json"),
    Path("specs/norn-knot-rc1/test-summary.json"),
}
IMAGE_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,})"),
    re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(rb"https?://[^/@\s]+:[^/@\s]+@"),
)
FORBIDDEN_SUFFIXES = (
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".keystore",
    ".jks",
)


class FinalizeError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FinalizeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise FinalizeError(f"{path} must contain an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _assert_clean_content(path: Path, content: bytes) -> None:
    if any(pattern.search(content) for pattern in SECRET_PATTERNS):
        raise FinalizeError(f"secret pattern detected in {path}")


def _scan_archive(path: Path) -> int:
    count = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise FinalizeError(f"unsafe archive member: {member.name}")
            if member.isfile() and member.name.lower().endswith(FORBIDDEN_SUFFIXES):
                raise FinalizeError(f"runtime or secret file in archive: {member.name}")
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                continue
            source = archive.extractfile(member)
            if source is None:
                raise FinalizeError(f"cannot inspect archive member: {member.name}")
            _assert_clean_content(path / member.name, source.read())
            count += 1
    return count


def _validate_acceptance(source_commit: str) -> dict[str, dict[str, Any]]:
    records = {name: _json(REPO / path) for name, path in ACCEPTANCE_PATHS.items()}
    for name, record in records.items():
        if record.get("source_commit") != source_commit:
            raise FinalizeError(f"{name} acceptance source_commit mismatch")
        release_version = record.get("release_version")
        if name == "field":
            release_version = record.get("release", {}).get("version")
        if release_version != VERSION:
            raise FinalizeError(f"{name} acceptance release version mismatch")
    if records["multichain"].get("result") != "passed":
        raise FinalizeError("multichain acceptance did not pass")
    if records["field"].get("result") != "passed":
        raise FinalizeError("field acceptance did not pass")
    field_release = records["field"].get("release", {})
    if (
        field_release.get("production_trace_ready") is not True
        or field_release.get("field_package_ready") is not True
        or field_release.get("real_server_deployed") is not False
        or field_release.get("production_traffic_enabled") is not False
    ):
        raise FinalizeError("field acceptance deployment flags are invalid")
    trace = records["trace"]
    if (
        trace.get("production_trace_ready") is not True
        or trace.get("concurrency") != 128
        or trace.get("cross_talk_count") != 0
        or trace.get("time_window_matching") is not False
        or trace.get("failure_closed") is not True
        or trace.get("sqlite_integrity") != "ok"
        or trace.get("temporary_environment_cleaned") is not True
        or trace.get("secret_scan_clean") is not True
    ):
        raise FinalizeError("production Trace acceptance is incomplete")
    return records


def finalize(source_commit: str, release_root: Path, output: Path) -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    if head != source_commit:
        raise FinalizeError(f"HEAD {head} is not source commit {source_commit}")
    records = _validate_acceptance(source_commit)
    subprocess.run(
        ["sha256sum", "--check", "--strict", "SHA256SUMS"],
        cwd=release_root,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    manifest = _json(release_root / "release-manifest.json")
    if manifest.get("version") != VERSION or manifest.get("git_commit") != source_commit:
        raise FinalizeError("release manifest source or version mismatch")
    if (
        manifest.get("production_trace_ready") is not True
        or manifest.get("field_package_ready") is not True
        or manifest.get("real_server_deployed") is not False
        or manifest.get("production_traffic_enabled") is not False
    ):
        raise FinalizeError("release manifest deployment flags are invalid")
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != {"management", "rust", "knot", "norn", "nginx"}:
        raise FinalizeError("release manifest does not contain five images")
    if any(not isinstance(value, str) or not IMAGE_RE.fullmatch(value) for value in images.values()):
        raise FinalizeError("release manifest contains an unpinned image")

    packages: list[dict[str, Any]] = []
    archive_members = 0
    for record in manifest.get("packages", []):
        archive = release_root / str(record.get("filename", ""))
        if not archive.is_file() or _sha256(archive) != record.get("sha256"):
            raise FinalizeError(f"package digest mismatch: {archive.name}")
        archive_members += _scan_archive(archive)
        packages.append({"filename": archive.name, "sha256": record["sha256"]})
    if len(packages) != 3:
        raise FinalizeError("exactly three field packages are required")

    scan_paths = [
        *(REPO.glob("**/.env.example")),
        *(REPO / path for path in ACCEPTANCE_PATHS.values()),
        release_root / "release-manifest.json",
    ]
    for path in scan_paths:
        _assert_clean_content(path, path.read_bytes())

    output.mkdir(parents=True, exist_ok=True)
    for name in (
        "release-manifest.json",
        "SHA256SUMS",
        "network-matrix.json",
        "secret-requirements.json",
        "installation-order.md",
    ):
        shutil.copy2(release_root / name, output / name)
    offline = {
        "schema_version": "resolver-identity-offline-image-manifest-v1",
        "release_version": VERSION,
        "source_commit": source_commit,
        "images": images,
        "archives_included_in_git": False,
    }
    _write_json(output / "offline-image-manifest.json", offline)
    summary = {
        "schema_version": "resolver-identity-norn-knot-rc-acceptance-v1",
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "release_version": VERSION,
        "source_commit": source_commit,
        "acceptance": {
            name: {
                "result": record.get("result", "passed" if name == "trace" else None),
                "sha256": _sha256(REPO / ACCEPTANCE_PATHS[name]),
            }
            for name, record in records.items()
        },
        "test_counts": records["field"].get("test_counts", {}),
        "trace": {
            "scenario_count": len(records["trace"].get("results", {})),
            "concurrency": records["trace"]["concurrency"],
            "cross_talk_count": records["trace"]["cross_talk_count"],
        },
        "packages": packages,
        "images": images,
        "security_audit": {
            "result": "passed",
            "archives_scanned": len(packages),
            "archive_members_scanned": archive_members,
            "env_examples_scanned": len(list(REPO.glob("**/.env.example"))),
            "secrets_found": False,
        },
        "deployment": {
            "production_trace_ready": True,
            "field_package_ready": True,
            "real_server_deployed": False,
            "production_traffic_enabled": False,
        },
    }
    _write_json(output / "test-summary.json", summary)


def verify_evidence_diff(source_commit: str, evidence_commit: str) -> None:
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", source_commit, evidence_commit],
        cwd=REPO,
        text=True,
    ).splitlines()
    changed_paths = {Path(path) for path in changed}
    unexpected = sorted(path for path in changed_paths if path not in GENERATED_PATHS)
    if unexpected:
        raise FinalizeError("business source changed after acceptance: " + ", ".join(map(str, unexpected)))
    missing = sorted(path for path in ACCEPTANCE_PATHS.values() if path not in changed_paths)
    if missing:
        raise FinalizeError("acceptance evidence was not regenerated: " + ", ".join(map(str, missing)))
    for record in _validate_acceptance(source_commit).values():
        if record.get("source_commit") != source_commit:
            raise FinalizeError("acceptance source commit changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--source-commit", required=True)
    finalize_parser.add_argument("--release-root", type=Path, required=True)
    finalize_parser.add_argument("--output", type=Path, default=EVIDENCE_ROOT)
    verify_parser = subparsers.add_parser("verify-evidence-diff")
    verify_parser.add_argument("--source-commit", required=True)
    verify_parser.add_argument("--evidence-commit", default="HEAD")
    args = parser.parse_args()
    try:
        if args.command == "finalize":
            finalize(args.source_commit, args.release_root.resolve(), args.output.resolve())
        else:
            verify_evidence_diff(args.source_commit, args.evidence_commit)
    except (FinalizeError, OSError, subprocess.CalledProcessError) as error:
        print(f"release evidence error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
