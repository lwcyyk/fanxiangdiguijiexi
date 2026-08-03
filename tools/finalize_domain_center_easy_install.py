#!/usr/bin/env python3
"""Finalize or validate domain-center easy-install delivery evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = REPO / "specs" / "domain-center-easy-install"
ALLOWED_EVIDENCE_ROOTS = (Path("specs/domain-center-easy-install"), Path("artifacts/domain-center"))
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,})"),
    re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(rb"https?://[^/@\s]+:[^/@\s]+@"),
    re.compile(rb"(?i:(?:password|passphrase|secret|token|credential|api[_-]?key)\s*[:=]\s*[^\s\[\]]{8,})"),
)
PASS_STATUSES = frozenset({"passed", "pass", "success"})
EXTERNAL_UNEXECUTED = frozenset({"blocked", "not_run"})


class FinalizeError(RuntimeError):
    """Raised when delivery evidence violates the finalization boundary."""


def _generator() -> Any:
    path = REPO / "tools" / "build_domain_center_site_bundle.py"
    spec = importlib.util.spec_from_file_location("domain_center_delivery_generator", path)
    if spec is None or spec.loader is None:
        raise FinalizeError("cannot load domain-center delivery verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=REPO, text=True).strip()


def _require_commit(commit: str) -> str:
    if COMMIT_RE.fullmatch(commit) is None:
        raise FinalizeError("source_commit must be an exact lowercase 40-character commit hash")
    try:
        kind = _git("cat-file", "-t", commit)
    except subprocess.CalledProcessError as error:
        raise FinalizeError(f"source commit does not exist: {commit}") from error
    if kind != "commit":
        raise FinalizeError(f"source object is not a commit: {commit}")
    return commit


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FinalizeError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise FinalizeError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _scan_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise FinalizeError(f"secret-scan target is not a regular file: {path}")
    data = path.read_bytes()
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        raise FinalizeError(f"secret pattern detected in evidence/output: {path}")


def _scan_evidence_paths(delivery: Path, output: Path) -> None:
    for path in (delivery / "证据.json", delivery / "12-验收证据" / "证据.json"):
        _scan_file(path)
    if output.exists():
        if output.is_dir():
            paths = [path for path in output.rglob("*") if path.is_file()]
        else:
            paths = [output]
        for path in paths:
            _scan_file(path)


def _validate_source_binding(evidence: dict[str, Any], source_commit: str, delivery: Path) -> None:
    if evidence.get("source_commit") != source_commit:
        raise FinalizeError("delivery evidence source_commit is missing or mismatched")
    if evidence.get("real_server_deployed") is not False:
        raise FinalizeError("real_server_deployed must be false")
    if evidence.get("production_traffic_enabled") is not False:
        raise FinalizeError("production_traffic_enabled must be false")
    checks = evidence.get("checks")
    if not isinstance(checks, dict):
        raise FinalizeError("delivery evidence checks must be an object")
    for check_id, raw in checks.items():
        if not isinstance(raw, dict):
            raise FinalizeError(f"check {check_id} must be an object")
        status = raw.get("status")
        if status in PASS_STATUSES or status == "failed":
            record = raw.get("evidence")
            if not isinstance(record, dict) or record.get("source_commit") != source_commit:
                raise FinalizeError(f"executed check {check_id} has missing/mismatched source binding")
            path_text, expected = record.get("path"), record.get("sha256")
            if not isinstance(path_text, str) or not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise FinalizeError(f"executed check {check_id} has incomplete evidence digest binding")
            path = Path(path_text)
            if not path.is_absolute():
                path = delivery / path
            if not path.is_file() or path.is_symlink() or _sha256(path) != expected:
                raise FinalizeError(f"executed check {check_id} evidence is missing or hash-mismatched")
        elif status not in EXTERNAL_UNEXECUTED:
            raise FinalizeError(f"external check {check_id} has disallowed final status {status!r}")


def _summary(source_commit: str, delivery: Path, evidence: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    external = []
    for check_id, check in sorted(evidence["checks"].items()):
        external.append({"id": check_id, "status": check["status"]})
    return {
        "schema_version": "resolver-identity-domain-center-easy-install-test-summary-v1",
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "source_commit": source_commit,
        "delivery": {"path": str(delivery), "evidence_sha256": _sha256(delivery / "证据.json")},
        "local": [
            {"id": "delivery_verification", "status": "passed"},
            {"id": "false_production_flags", "status": "passed"},
            {"id": "evidence_secret_scan", "status": "passed"},
        ],
        "external": external,
        "blocked": bool(verification.get("blocked")),
        "real_server_deployed": False,
        "production_traffic_enabled": False,
    }


def validate_summary(path: Path, source_commit: str, delivery: Path) -> dict[str, Any]:
    summary = _load_object(path, "test summary")
    if summary.get("source_commit") != source_commit:
        raise FinalizeError("test summary source_commit is missing or mismatched")
    if summary.get("real_server_deployed") is not False or summary.get("production_traffic_enabled") is not False:
        raise FinalizeError("test summary production flags must be false")
    delivery_record = summary.get("delivery")
    if not isinstance(delivery_record, dict) or delivery_record.get("evidence_sha256") != _sha256(delivery / "证据.json"):
        raise FinalizeError("test summary evidence hash is missing or mismatched")
    local = summary.get("local")
    external = summary.get("external")
    if not isinstance(local, list) or not local or any(not isinstance(item, dict) or item.get("status") != "passed" for item in local):
        raise FinalizeError("test summary must list local checks as passed")
    if not isinstance(external, list) or any(not isinstance(item, dict) or item.get("status") not in EXTERNAL_UNEXECUTED | PASS_STATUSES | {"failed"} for item in external):
        raise FinalizeError("test summary external status vocabulary is invalid")
    return summary


def finalize(source_commit: str, delivery: Path, output: Path, *, allow_blocked: bool) -> dict[str, Any]:
    source_commit = _require_commit(source_commit)
    head = _git("rev-parse", "HEAD")
    if head != source_commit:
        raise FinalizeError(f"finalize must run at Source Commit: HEAD={head}, source={source_commit}")
    verification = _generator().verify_delivery(delivery, allow_blocked=allow_blocked)
    if verification.get("blocked") and not allow_blocked:
        raise FinalizeError("delivery remains blocked; pass --allow-blocked only to record blocked/not_run external work")
    evidence = _load_object(delivery / "证据.json", "delivery evidence")
    _validate_source_binding(evidence, source_commit, delivery)
    _scan_evidence_paths(delivery, output)
    summary = _summary(source_commit, delivery, evidence, verification)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_summary(output, source_commit, delivery)
    _scan_file(output)
    return summary


def _allowed_evidence_path(path: Path) -> bool:
    return any(path == root or root in path.parents for root in ALLOWED_EVIDENCE_ROOTS)


def verify_evidence_diff(source_commit: str, evidence_commit: str) -> None:
    source_commit = _require_commit(source_commit)
    evidence_commit = _git("rev-parse", f"{evidence_commit}^{{commit}}")
    if _git("rev-parse", "HEAD") != evidence_commit:
        raise FinalizeError("verify-evidence-diff must run with HEAD at Evidence Commit")
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", source_commit, evidence_commit],
            cwd=REPO,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise FinalizeError("Source Commit is not an ancestor of Evidence Commit") from error
    changed = _git("-c", "core.quotePath=false", "diff", "--name-only", source_commit, evidence_commit).splitlines()
    if not changed:
        raise FinalizeError("evidence commit contains no tracked evidence changes")
    unexpected = [path for path in map(Path, changed) if not _allowed_evidence_path(path)]
    if unexpected:
        raise FinalizeError("evidence-only commit changed source/config/script paths: " + ", ".join(map(str, unexpected)))
    summaries = [Path(path) for path in changed if Path(path).name == "test-summary.json"]
    if not summaries:
        raise FinalizeError("evidence commit must include test-summary.json")
    for path in summaries:
        value = _load_object(REPO / path, "test summary")
        if value.get("source_commit") != source_commit:
            raise FinalizeError(f"{path} source_commit is missing or mismatched")
        delivery = value.get("delivery")
        if not isinstance(delivery, dict) or not isinstance(delivery.get("evidence_sha256"), str):
            raise FinalizeError(f"{path} is missing exact evidence hash binding")
    for path_text in changed:
        path = REPO / path_text
        if path.is_file():
            _scan_file(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("finalize")
    create.add_argument("--source-commit", required=True)
    create.add_argument("--delivery", required=True, type=Path)
    create.add_argument("--output", type=Path, default=EVIDENCE_ROOT / "test-summary.json")
    create.add_argument("--allow-blocked", action="store_true", help="validate structural delivery while preserving external blocked/not_run statuses")
    check = commands.add_parser("validate-summary")
    check.add_argument("--source-commit", required=True)
    check.add_argument("--delivery", required=True, type=Path)
    check.add_argument("--summary", required=True, type=Path)
    diff = commands.add_parser("verify-evidence-diff")
    diff.add_argument("--source-commit", required=True)
    diff.add_argument("--evidence-commit", default="HEAD")
    args = parser.parse_args()
    try:
        if args.command == "finalize":
            result = finalize(args.source_commit, args.delivery.resolve(), args.output.resolve(), allow_blocked=args.allow_blocked)
            print(json.dumps({"finalized": True, "blocked": result["blocked"], "summary": str(args.output)}, ensure_ascii=False, sort_keys=True))
        elif args.command == "validate-summary":
            _require_commit(args.source_commit)
            validate_summary(args.summary.resolve(), args.source_commit, args.delivery.resolve())
            print(json.dumps({"valid": True}, sort_keys=True))
        else:
            verify_evidence_diff(args.source_commit, args.evidence_commit)
            print(json.dumps({"evidence_diff": "valid"}, sort_keys=True))
    except (FinalizeError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"domain-center evidence error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
