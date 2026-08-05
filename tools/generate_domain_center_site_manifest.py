#!/usr/bin/env python3
"""Generate test-only site/release manifests from an inventory and verified OCI archives."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import yaml

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "tools" / "build_domain_center_site_bundle.py"
spec = importlib.util.spec_from_file_location("domain_center_bundle_builder", BUILDER_PATH)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

VERSION = "0.3.1-norn-knot-rc3"
SOURCE_COMMIT = "8c14b7a656286b9a021ec3171d2ea01486821abb"
IMAGE_FILES = {
    "management": "management.oci.tar",
    "rust": "rust-data-plane.oci.tar",
    "knot": "knot-trace.oci.tar",
    "norn": "go-norn.oci.tar",
    "nginx": "mtls-read-proxy.oci.tar",
}
ROLE_NAMES = {"management", "norn-a", "norn-b", "r1", "r2", "r3"}


def write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(data, encoding="utf-8")
    return hashlib.sha256(data.encode()).hexdigest()


def read_inventory(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("inventory must be a regular file")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("environment") != "test-only":
        raise ValueError("inventory environment must be test-only")
    hosts = value.get("hosts")
    if not isinstance(hosts, list):
        raise ValueError("inventory hosts must be an array")
    formal = [host for host in hosts if isinstance(host, dict) and host.get("role") in ROLE_NAMES]
    if len(formal) != 6 or {host.get("role") for host in formal} != ROLE_NAMES:
        raise ValueError("inventory must contain exactly one host for each formal role")
    return value


def archive_metadata(path: Path, repository: str) -> dict[str, Any]:
    with tarfile.open(path, "r:*") as archive:
        members = {member.name: member for member in archive.getmembers()}
        index = json.loads(archive.extractfile(members["index.json"]).read())
        manifests = index.get("manifests", [])
        if len(manifests) != 1:
            raise ValueError(f"{path} must contain exactly one OCI manifest")
        descriptor = manifests[0]
        digest = descriptor["digest"]
        annotation = descriptor.get("annotations", {}).get(builder.OCI_REF_ANNOTATION)
        if not annotation:
            raise ValueError(f"{path} has no OCI image annotation")
    checked = builder.validate_oci_archive(path, digest, {"os": "linux", "architecture": "amd64"}, builder._import_reference(repository, digest), annotation)
    if checked.get("image_source_commit") is None:
        raise ValueError(f"{path} has no verifiable image source commit provenance")
    if checked["image_source_commit"] != SOURCE_COMMIT:
        raise ValueError(f"{path} source commit is not {SOURCE_COMMIT}")
    return {
        "archive": str(path),
        "archive_sha256": checked["archive_sha256"],
        "image_reference": f"{repository}@{digest}",
        "image_annotation": annotation,
        "image_manifest_digest": digest,
        "config_digest": checked["config_digest"],
        "layer_digests": checked["layer_digests"],
        "image_source_commit": checked["image_source_commit"],
        "platform": checked["platform"],
    }


def host_records(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for host in inventory["hosts"]:
        if host.get("role") not in ROLE_NAMES:
            continue
        records.append({
            "hostname": host["hostname"],
            "fqdn": host["fqdn"],
            "management_ip": host["management_ipv4"],
            "machine_id": host["machine_id"],
            "role": host["role"],
            "architecture": "amd64" if host.get("architecture") in {"x86_64", "amd64"} else host.get("architecture"),
            "transit_interfaces": [
                {"name": interface["name"], "ipv4": interface["ipv4"], "network": interface["network"]}
                for interface in host.get("interfaces", [])
            ],
        })
    return sorted(records, key=lambda record: record["hostname"])


def impact_audit(source_commit: str, output_dir: Path) -> dict[str, Any]:
    try:
        changed = subprocess.check_output(["git", "diff", "--name-only", "3ffe929c1913f78da5a6293e35a075d2d2927344", source_commit], text=True).splitlines()
    except subprocess.CalledProcessError as exc:
        raise ValueError("cannot inspect RC3 source diff") from exc
    rows = []
    for name in changed:
        management_oci = name.startswith("src/") or name == "tools/manage_v2_registry.py"
        host_package = name.startswith("deploy/easy-install/product-kit/")
        rows.append({
            "changed_file": name,
            "included_in_host_package": host_package,
            "included_in_management_oci": management_oci,
            "included_in_other_oci": False,
            "runtime_effect": "Management runtime/key contract" if management_oci else ("all easy-install host packages" if host_package else "delivery metadata/tests/docs"),
            "artifact_rebuild_required": "management OCI and host packages" if management_oci else ("host packages" if host_package else "no OCI payload rebuild"),
            "evidence": "git diff --name-only 3ffe929c1913f78da5a6293e35a075d2d2927344.." + source_commit,
        })
    result = {
        "schema_version": "domain-center-rc3-artifact-impact-audit-v1",
        "release_version": VERSION,
        "source_commit": source_commit,
        "rows": rows,
        "oci_reuse": {
            "management": {"decision": "rebuild", "reason": "RC3 changes enter Dockerfile.management source graph"},
            "rust": {"decision": "blocked", "reason": "old archive has no verifiable source commit provenance"},
            "knot": {"decision": "blocked", "reason": "old archive has no verifiable source commit provenance"},
            "norn": {"decision": "blocked", "reason": "old archive has no verifiable source commit provenance"},
            "nginx": {"decision": "blocked", "reason": "old archive has no verifiable source commit provenance"},
        },
    }
    write_json(output_dir / "artifact-impact-audit.json", result)
    lines = ["# RC3 artifact impact audit", "", f"- release_version: `{VERSION}`", f"- source_commit: `{source_commit}`", "", "| changed_file | host package | Management OCI | other OCI | rebuild |", "|---|---:|---:|---:|---|"]
    lines.extend(f"| `{row['changed_file']}` | {row['included_in_host_package']} | {row['included_in_management_oci']} | {row['included_in_other_oci']} | `{row['artifact_rebuild_required']}` |" for row in rows)
    lines += ["", "## OCI reuse", "", "Old RC1 archives retain their actual annotations and are not relabeled as RC3. Missing source provenance blocks reuse.", ""]
    (output_dir / "artifact-impact-audit.md").write_text("\n".join(lines), encoding="utf-8")
    return result


def generate(args: argparse.Namespace) -> int:
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    audit = impact_audit(args.source_commit, out.parent)
    inventory = read_inventory(args.inventory.resolve())
    records: dict[str, dict[str, Any]] = {}
    blocked: list[str] = []
    for key, filename in IMAGE_FILES.items():
        try:
            records[key] = archive_metadata(args.oci_root.resolve() / filename, f"offline/resolver-identity/{key}")
        except (OSError, KeyError, tarfile.TarError, ValueError, builder.BundleError) as exc:
            blocked.append(f"{key}: {exc}")
    result: dict[str, Any] = {
        "schema_version": "domain-center-rc3-generation-result-v1",
        "environment": "test-only",
        "single_physical_hypervisor": True,
        "formal_release_asset": False,
        "formal_six_host_acceptance": False,
        "release_ready": False,
        "authenticity": "blocked",
        "verification_mode": "structural-only",
        "source_commit": args.source_commit,
        "version": args.version,
        "artifact_impact_audit": str((out.parent / "artifact-impact-audit.json").resolve()),
        "oci": records,
        "blocked": blocked,
        "status": "blocked" if blocked else "generated",
        "rc3_candidate_generation": "blocked" if blocked else "continue",
        "reason": "official_site_manifest_input_unresolved" if blocked else None,
    }
    write_json(out / "generation-result.json", result)
    if blocked:
        return 2
    release = {"version": args.version, "git_commit": args.source_commit, "images": {key: record["image_reference"] for key, record in records.items()}, "image_metadata": records}
    release_sha = write_json(out / "release-manifest.json", release)
    site = {
        "schema_version": builder.SCHEMA,
        "release": {"version": args.version, "source_commit": args.source_commit, "manifest_sha256": release_sha},
        "platform": {"os": "linux", "architecture": "amd64"},
        "hosts": host_records(inventory),
        "images": {key: {"archive": record["archive"], "repository": f"offline/resolver-identity/{key}", "image_annotation": record["image_annotation"], "image_source_commit": record["image_source_commit"]} for key, record in records.items()},
        "external_requirements": {requirement_id: {"status": "not_run", "status_zh": "未运行", "reason_zh": "test-only 输入生成未执行现场验收。"} for requirement_id in sorted(builder.REQUIRED_EXTERNAL_ACCEPTANCE_IDS)},
    }
    write_json(out / "site-manifest.json", site)
    write_json(out / "images.lock.json", {"schema_version": "domain-center-rc3-image-lock-v1", "environment": "test-only", "release_version": args.version, "source_commit": args.source_commit, "images": records})
    result["release_manifest_sha256"] = release_sha
    result["status"] = "generated"
    write_json(out / "generation-result.json", result)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--oci-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--environment", choices=("test-only",), required=True)
    args = parser.parse_args()
    if args.version != VERSION or args.source_commit != SOURCE_COMMIT:
        parser.error("this RC3 test-only generator is fixed to the approved version and source commit")
    try:
        return generate(args)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
