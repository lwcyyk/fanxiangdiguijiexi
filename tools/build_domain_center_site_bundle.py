#!/usr/bin/env python3
"""Build and verify deterministic, offline domain-center site deliveries."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

SCHEMA = "resolver-identity-domain-center-easy-site-v1"
EVIDENCE_SCHEMA = "resolver-identity-domain-center-easy-evidence-v1"
LOCK_SCHEMA = "resolver-identity-role-image-lock-v1"
SPDX_VERSION = "SPDX-2.3"
CDX_VERSION = "1.5"
DELIVERY_PREFIX = "resolver-identity-domain-center-easy-install"
REQUIRED_EXTERNAL_ACCEPTANCE_IDS = frozenset(
    {
        "resolver_trace",
        "production_cutover",
        "pki_identity",
        "network_isolation",
        "negative_fail_close",
        "monitoring",
        "backup_restore",
        "capacity",
        "rollback_rto",
        "ubuntu22",
        "ubuntu24",
        "real_oci",
    }
)
STATUS_VOCABULARY = {
    "passed": {"通过", "已通过", "passed"},
    "pass": {"通过", "已通过", "pass"},
    "success": {"通过", "已通过", "成功", "success"},
    "blocked": {"阻断", "已阻断", "blocked"},
    "not_run": {"未运行", "未执行", "not_run"},
    "failed": {"失败", "未通过", "failed"},
    "pending": {"待处理", "待验收", "pending"},
}
TOP_LEVEL_DIRECTORIES = (
    "00-开始",
    "01-发布信息",
    "02-校验与签名",
    "03-主机包",
    "04-软件物料清单",
    "05-PDF手册",
    "06-配置交接",
    "07-证书与身份",
    "08-网络隔离",
    "09-监控",
    "10-备份恢复",
    "11-容量与回滚",
    "12-验收证据",
)
OCI_REF_ANNOTATION = "org.opencontainers.image.ref.name"
ROLE_COUNTS = {
    "management": 1,
    "norn-a": 1,
    "norn-b": 1,
    "r1": 1,
    "r2": 1,
    "r3": 1,
}
ROLE_TEMPLATE = {role: role for role in ROLE_COUNTS}
ROLE_IMAGES = {
    "management": ("management", "norn"),
    "norn-a": ("norn", "nginx"),
    "norn-b": ("norn", "nginx"),
    "r1": ("rust", "knot"),
    "r2": ("rust", "knot"),
    "r3": ("rust", "knot"),
}
CHINESE_ENTRY_POINTS = {
    "开始安装.sh": "install",
    "检查运行状态.sh": "status",
    "准备证书和密钥.sh": "prepare-secrets",
    "导出故障信息.sh": "support",
    "备份.sh": "backup",
    "回滚.sh": "rollback",
    "卸载.sh": "uninstall",
}
ASCII_ENTRY_POINTS = {
    "install": "install",
    "status": "status",
    "prepare-secrets": "prepare-secrets",
    "support": "support",
    "backup": "backup",
    "rollback": "rollback",
    "uninstall": "uninstall",
}
EXPECTED_IMAGE_KEYS = frozenset({"management", "rust", "knot", "norn", "nginx"})
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    }
)
SHA256_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,125}[A-Za-z0-9])?$")
IMAGE_REF_RE = re.compile(r"^([^@\s]+)@sha256:([0-9a-f]{64})$")
SECRET_KEY_RE = re.compile(
    r"(?:private.?key|password|passphrase|mnemonic|secret|token|credential|api.?key)",
    re.IGNORECASE,
)
SECRET_BYTES_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|"
    rb"(?:gh[pousr]_[A-Za-z0-9]{30,})|(?:AKIA|ASIA)[A-Z0-9]{16}"
)
FORBIDDEN_OUTPUT_RE = (
    (re.compile(rb"127\.0\.0\.1"), "loopback image/reference text"),
    (re.compile(rb":latest(?:[^A-Za-z0-9_.-]|$)", re.IGNORECASE), "latest image reference"),
    (
        re.compile(rb"(?:docker|podman|nerdctl|crictl)[ \t]+(?:image[ \t]+)?pull\b", re.IGNORECASE),
        "runtime image pull command",
    ),
    (re.compile(rb"pull_policy[ \t]*:", re.IGNORECASE), "runtime pull policy"),
)


class BundleError(ValueError):
    """Raised when input or output violates the delivery policy."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON/YAML-subset key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(
            f"{label} must be UTF-8 JSON (the duplicate-key-safe JSON-compatible YAML subset): {error}"
        ) from error


def load_json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"{label} is not duplicate-key-safe UTF-8 JSON: {error}") from error


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BundleError(f"{label} must be an array")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BundleError(f"{label} must be a non-empty trimmed string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BundleError(f"{label} contains control characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise BundleError(f"{label} has an invalid format")
    return value


def _exact_keys(value: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise BundleError(f"{label} fields are invalid: {'; '.join(details)}")


def _reject_secret_fields(value: Any, label: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_KEY_RE.search(key):
                raise BundleError(f"{label}.{key} is a prohibited secret-bearing field")
            _reject_secret_fields(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{label}[{index}]")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_stream(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        size += len(chunk)
        digest.update(chunk)
    return digest.hexdigest(), size


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_json_bytes(value))
    path.chmod(0o644)


def _safe_relative(name: str, label: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or name.startswith("/") or "\\" in name or ".." in path.parts or "." in path.parts:
        raise BundleError(f"{label} has an unsafe archive path: {name}")
    return path


def _descriptor(value: Any, label: str, media_types: frozenset[str] | set[str]) -> dict[str, Any]:
    item = _object(value, label)
    _exact_keys(item, {"mediaType", "digest", "size"}, {"platform", "annotations", "urls"}, label)
    media_type = _text(item["mediaType"], f"{label}.mediaType")
    if media_type not in media_types:
        raise BundleError(f"{label}.mediaType is not an approved OCI media type")
    digest = _text(item["digest"], f"{label}.digest")
    if SHA256_RE.fullmatch(digest) is None:
        raise BundleError(f"{label}.digest must be lowercase sha256")
    size = item["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BundleError(f"{label}.size must be a non-negative integer")
    return item


def _read_member(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> bytes:
    info = members.get(name)
    if info is None or not info.isfile():
        raise BundleError(f"OCI archive is missing regular file {name}")
    handle = archive.extractfile(info)
    if handle is None:
        raise BundleError(f"cannot read OCI member {name}")
    return handle.read()


def _validate_layer_tar(data: bytes, media_type: str, label: str) -> str:
    try:
        raw = gzip.decompress(data) if media_type.endswith("+gzip") else data
    except (OSError, EOFError) as error:
        raise BundleError(f"{label} is not valid gzip data: {error}") from error
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as layer:
            seen: set[str] = set()
            for member in layer:
                normalized = _safe_relative(member.name, label).as_posix()
                if normalized in seen:
                    raise BundleError(f"{label} contains duplicate member {normalized}")
                seen.add(normalized)
                if member.issym() or member.islnk():
                    target = PurePosixPath(member.linkname)
                    if member.linkname.startswith("/") or ".." in target.parts:
                        raise BundleError(f"{label} contains escaping link {normalized}")
                elif not (member.isfile() or member.isdir() or member.ischr() or member.isblk() or member.isfifo()):
                    raise BundleError(f"{label} contains unsupported member {normalized}")
    except tarfile.TarError as error:
        raise BundleError(f"{label} is not a valid layer tar: {error}") from error
    return hashlib.sha256(raw).hexdigest()


def _import_reference(repository: str, digest: str) -> str:
    """Return a deterministic, importable OCI tag associated with a pinned digest."""
    return f"{repository}:ri-{digest.split(':', 1)[1][:16]}"


def validate_oci_archive(
    path: Path,
    expected_digest: str,
    platform: dict[str, str],
    expected_reference: str | None = None,
) -> dict[str, Any]:
    """Fully validate one strict, single-platform OCI image-layout tar."""
    if not path.is_file() or path.is_symlink():
        raise BundleError(f"OCI archive is not a regular file: {path}")
    try:
        archive = tarfile.open(path, mode="r:*")
    except (OSError, tarfile.TarError) as error:
        raise BundleError(f"cannot open OCI archive {path}: {error}") from error
    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for info in archive:
            name = _safe_relative(info.name, f"OCI archive {path}").as_posix()
            if name in members:
                raise BundleError(f"OCI archive contains duplicate member: {name}")
            if info.issym() or info.islnk() or not (info.isfile() or info.isdir()):
                raise BundleError(f"OCI archive contains a non-regular unsupported member: {name}")
            members[name] = info
        layout = _object(load_json_bytes(_read_member(archive, members, "oci-layout"), "oci-layout"), "oci-layout")
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise BundleError("oci-layout must contain exactly imageLayoutVersion 1.0.0")
        index = _object(load_json_bytes(_read_member(archive, members, "index.json"), "index.json"), "index.json")
        _exact_keys(index, {"schemaVersion", "manifests"}, {"mediaType", "annotations"}, "index.json")
        if index["schemaVersion"] != 2:
            raise BundleError("OCI index schemaVersion must be 2")
        manifests = _array(index["manifests"], "index.json.manifests")
        if len(manifests) != 1:
            raise BundleError("OCI index must contain exactly one manifest descriptor")
        root = _descriptor(manifests[0], "index.json.manifests[0]", {OCI_MANIFEST})
        if root["digest"] != expected_digest:
            raise BundleError(f"OCI manifest digest {root['digest']} does not equal release digest {expected_digest}")
        if expected_reference is not None:
            annotations = _object(root.get("annotations"), "index manifest annotations")
            reference_name = annotations.get(OCI_REF_ANNOTATION)
            if reference_name != expected_reference:
                raise BundleError(
                    f"OCI index manifest annotation {OCI_REF_ANNOTATION} must equal configured reference {expected_reference}"
                )
        root_platform = _object(root.get("platform"), "index manifest platform")
        required_platform = {"os": platform["os"], "architecture": platform["architecture"]}
        if platform.get("variant"):
            required_platform["variant"] = platform["variant"]
        if root_platform != required_platform:
            raise BundleError(f"OCI index platform must equal {required_platform}")

        referenced: set[str] = set()

        def blob(descriptor: dict[str, Any], label: str) -> bytes:
            digest_hex = SHA256_RE.fullmatch(descriptor["digest"]).group(1)  # type: ignore[union-attr]
            name = f"blobs/sha256/{digest_hex}"
            data = _read_member(archive, members, name)
            if len(data) != descriptor["size"] or hashlib.sha256(data).hexdigest() != digest_hex:
                raise BundleError(f"{label} blob size or sha256 does not match its descriptor")
            referenced.add(name)
            return data

        manifest = _object(load_json_bytes(blob(root, "manifest"), "OCI manifest"), "OCI manifest")
        _exact_keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, {"annotations", "artifactType", "subject"}, "OCI manifest")
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
            raise BundleError("OCI manifest must be schemaVersion 2 with OCI manifest mediaType")
        config_desc = _descriptor(manifest["config"], "OCI manifest config", {OCI_CONFIG})
        layer_descs = [
            _descriptor(item, f"OCI manifest layers[{index}]", OCI_LAYER_TYPES)
            for index, item in enumerate(_array(manifest["layers"], "OCI manifest layers"))
        ]
        if not layer_descs:
            raise BundleError("OCI manifest must contain at least one layer")
        config = _object(load_json_bytes(blob(config_desc, "config"), "OCI config"), "OCI config")
        if config.get("os") != platform["os"] or config.get("architecture") != platform["architecture"]:
            raise BundleError("OCI config os/architecture does not match requested platform")
        if platform.get("variant") and config.get("variant") != platform["variant"]:
            raise BundleError("OCI config variant does not match requested platform")
        rootfs = _object(config.get("rootfs"), "OCI config rootfs")
        if rootfs.get("type") != "layers":
            raise BundleError("OCI config rootfs.type must be layers")
        diff_ids = _array(rootfs.get("diff_ids"), "OCI config rootfs.diff_ids")
        if len(diff_ids) != len(layer_descs):
            raise BundleError("OCI config diff_ids count must equal layer count")
        for index, descriptor in enumerate(layer_descs):
            layer_data = blob(descriptor, f"layer {index}")
            diff_id = _validate_layer_tar(layer_data, descriptor["mediaType"], f"layer {index}")
            if diff_ids[index] != f"sha256:{diff_id}":
                raise BundleError(f"layer {index} uncompressed diff_id does not match config")
        actual_blobs = {name for name, info in members.items() if info.isfile() and name.startswith("blobs/")}
        if actual_blobs != referenced:
            extra = sorted(actual_blobs - referenced)
            raise BundleError(f"OCI archive contains unreferenced or non-sha256 blobs: {extra}")
        allowed_files = {"oci-layout", "index.json", *referenced}
        actual_files = {name for name, info in members.items() if info.isfile()}
        if actual_files != allowed_files:
            raise BundleError("OCI archive contains unexpected regular files")
    return {
        "archive_sha256": _sha256(path),
        "manifest_digest": expected_digest,
        "platform": required_platform,
        "layer_count": len(layer_descs),
    }


def validate_inputs(site_path: Path, release_path: Path) -> dict[str, Any]:
    site = _object(load_json(site_path, "site manifest"), "site manifest")
    release = _object(load_json(release_path, "source release manifest"), "source release manifest")
    _reject_secret_fields(site)
    _reject_secret_fields(release, "source release manifest")
    _exact_keys(site, {"schema_version", "release", "platform", "hosts", "images"}, {"external_requirements"}, "site manifest")
    if site["schema_version"] != SCHEMA:
        raise BundleError(f"schema_version must be {SCHEMA}")
    site_release = _object(site["release"], "release")
    _exact_keys(site_release, {"version", "source_commit", "manifest_sha256"}, set(), "release")
    version = _text(site_release["version"], "release.version", VERSION_RE)
    commit = _text(site_release["source_commit"], "release.source_commit", COMMIT_RE)
    manifest_sha = _text(site_release["manifest_sha256"], "release.manifest_sha256")
    if re.fullmatch(r"[0-9a-f]{64}", manifest_sha) is None:
        raise BundleError("release.manifest_sha256 must be lowercase SHA-256")
    if manifest_sha != _sha256(release_path):
        raise BundleError("release.manifest_sha256 does not match the exact source release manifest")
    if release.get("version") != version or release.get("git_commit") != commit:
        raise BundleError("site version/source commit does not exactly match source release manifest")
    source_images = _object(release.get("images"), "source release images")
    if set(source_images) != EXPECTED_IMAGE_KEYS:
        raise BundleError("source release manifest must contain exactly the five approved images")

    platform = _object(site["platform"], "platform")
    _exact_keys(platform, {"os", "architecture"}, {"variant"}, "platform")
    platform_clean = {
        "os": _text(platform["os"], "platform.os"),
        "architecture": _text(platform["architecture"], "platform.architecture"),
    }
    if "variant" in platform:
        platform_clean["variant"] = _text(platform["variant"], "platform.variant")
    if platform_clean["os"] != "linux":
        raise BundleError("only linux OCI images are accepted")

    images = _object(site["images"], "images")
    if set(images) != EXPECTED_IMAGE_KEYS:
        raise BundleError("images must contain exactly management, rust, knot, norn, and nginx")
    clean_images: dict[str, Any] = {}
    for key in sorted(images):
        item = _object(images[key], f"images.{key}")
        _exact_keys(item, {"archive", "repository"}, set(), f"images.{key}")
        archive = Path(_text(item["archive"], f"images.{key}.archive"))
        if not archive.is_absolute():
            archive = (site_path.parent / archive).resolve()
        repository = _text(item["repository"], f"images.{key}.repository")
        if "@" in repository or repository.endswith(":latest") or repository.startswith("127.0.0.1"):
            raise BundleError(f"images.{key}.repository must be a non-loopback repository without tag/digest")
        source_ref = _text(source_images[key], f"source release images.{key}")
        match = IMAGE_REF_RE.fullmatch(source_ref)
        if match is None:
            raise BundleError(f"source release images.{key} is not digest-pinned")
        digest = f"sha256:{match.group(2)}"
        reference = f"{repository.rstrip('/')}@{digest}"
        import_reference = _import_reference(repository.rstrip('/'), digest)
        oci = validate_oci_archive(archive, digest, platform_clean, import_reference)
        clean_images[key] = {
            "archive": archive,
            "repository": repository.rstrip("/"),
            "reference": reference,
            "import_reference": import_reference,
            "digest": digest,
            **oci,
        }

    hosts = [_object(item, f"hosts[{index}]") for index, item in enumerate(_array(site["hosts"], "hosts"))]
    if len(hosts) != 6:
        raise BundleError("hosts must contain exactly six entries")
    counts = {role: 0 for role in ROLE_COUNTS}
    names: list[str] = []
    clean_hosts: list[dict[str, str]] = []
    for index, host in enumerate(hosts):
        _exact_keys(host, {"hostname", "role"}, set(), f"hosts[{index}]")
        hostname = _text(host["hostname"], f"hosts[{index}].hostname", HOST_RE)
        role = _text(host["role"], f"hosts[{index}].role")
        if role not in ROLE_COUNTS:
            raise BundleError(f"hosts[{index}].role is not approved")
        counts[role] += 1
        names.append(hostname)
        clean_hosts.append({"hostname": hostname, "role": role})
    if counts != ROLE_COUNTS:
        raise BundleError(f"six-host role counts must equal {ROLE_COUNTS}")
    if len(set(names)) != len(names):
        raise BundleError("hostnames must be unique")
    requirements = _object(site.get("external_requirements", {}), "external_requirements")
    missing_requirements = REQUIRED_EXTERNAL_ACCEPTANCE_IDS - set(requirements)
    if missing_requirements:
        raise BundleError(
            "external_requirements is missing mandatory acceptance IDs: "
            + ", ".join(sorted(missing_requirements))
        )
    clean_requirements: dict[str, dict[str, str]] = {}
    for requirement_id, raw_requirement in sorted(requirements.items()):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", requirement_id) is None:
            raise BundleError(f"external requirement id is invalid: {requirement_id!r}")
        requirement = _object(raw_requirement, f"external_requirements.{requirement_id}")
        _exact_keys(requirement, {"status", "status_zh"}, {"reason_zh", "blocked_by"}, f"external_requirements.{requirement_id}")
        status = _text(requirement["status"], f"external_requirements.{requirement_id}.status").lower()
        status_zh = _text(requirement["status_zh"], f"external_requirements.{requirement_id}.status_zh")
        if status not in STATUS_VOCABULARY or status_zh not in STATUS_VOCABULARY[status]:
            raise BundleError(
                f"external_requirements.{requirement_id} has an unsupported or inconsistent status/status_zh"
            )
        clean_requirement = {"status": status, "status_zh": status_zh}
        if "reason_zh" in requirement:
            clean_requirement["reason_zh"] = _text(requirement["reason_zh"], f"external_requirements.{requirement_id}.reason_zh")
        if "blocked_by" in requirement:
            clean_requirement["blocked_by"] = _text(requirement["blocked_by"], f"external_requirements.{requirement_id}.blocked_by")
        clean_requirements[requirement_id] = clean_requirement
    return {
        "version": version,
        "source_commit": commit,
        "release_manifest_sha256": manifest_sha,
        "platform": platform_clean,
        "hosts": sorted(clean_hosts, key=lambda item: item["hostname"]),
        "images": clean_images,
        "external_requirements": clean_requirements,
    }


def _copy_template(source: Path, destination: Path, replacements: dict[str, str]) -> None:
    if not source.is_dir() or source.is_symlink():
        raise BundleError(f"required product-kit template directory is unavailable: {source}")
    destination.mkdir(parents=True, mode=0o755)
    os.chmod(destination, 0o755)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            raise BundleError(f"product-kit templates must not contain symlinks: {path}")
        if path.is_dir():
            target.mkdir(mode=0o755)
            continue
        data = path.read_bytes()
        if SECRET_BYTES_RE.search(data):
            raise BundleError(f"product-kit template contains private credential material: {path}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            target.write_bytes(data)
        else:
            for marker, replacement in replacements.items():
                text = text.replace(marker, replacement)
            if path.name == "PACKAGE-VERSION":
                text = replacements["{{VERSION}}"] + "\n"
            if "{{" in text or "}}" in text:
                raise BundleError(f"unresolved product-kit placeholder in {path}")
            target.write_text(text, encoding="utf-8")
        target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)


def _entry_script(root_expression: str, action: str, role: str, hostname: str) -> str:
    return f'''#!/bin/sh
set -eu
ROOT={root_expression}
exec python3 "$ROOT/wizard.py" {action} --package-root "$ROOT/product-kit" --role {role} --expected-host {hostname} --images "$ROOT/images" "$@"
'''


def _write_host_entry_points(host_root: Path, role: str, hostname: str) -> None:
    scripts = host_root / "scripts"
    _mkdir(scripts)
    root_expression = '$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)'
    nested_root_expression = '$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)'
    for filename, action in CHINESE_ENTRY_POINTS.items():
        path = host_root / filename
        path.write_text(_entry_script(root_expression, action, role, hostname), encoding="utf-8")
        path.chmod(0o755)
    for name, action in ASCII_ENTRY_POINTS.items():
        path = scripts / f"{name}.sh"
        path.write_text(_entry_script(nested_root_expression, action, role, hostname), encoding="utf-8")
        path.chmod(0o755)


def _host_readme(hostname: str, role: str) -> str:
    return f"""域名中心离线主机安装包

指定主机：{hostname}
固定角色：{role}

1. 校验 SHA256SUMS 后解压到本机普通目录。
2. 执行 ./准备证书和密钥.sh --secret-dir /绝对路径/secrets --install-root /opt/domain-center。
3. 材料准备后执行 ./开始安装.sh --config-dir /绝对路径/config --secret-dir /绝对路径/secrets --install-root /opt/domain-center --yes。
4. 运行 ./检查运行状态.sh 查看机器可读状态。

ASCII 入口位于 scripts/。安装包只准备离线制品，不表示真实服务器已部署，也不表示生产流量已启用。
"""


def _write_checksums(root: Path, destination: Path, excluded: set[Path] | None = None) -> None:
    excluded = excluded or set()
    paths = [
        path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path not in excluded and path != destination
    ]
    lines = [f"{_sha256(path)}  {path.relative_to(root).as_posix()}" for path in sorted(paths)]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    destination.chmod(0o644)


def _mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.chmod(0o755)


def _write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def _status_passed(status: str) -> bool:
    return status in {"passed", "pass", "success"}


def _recipient_verify_script() -> str:
    return '''#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PINNED_KEY=${1:-}
PINNED_FINGERPRINT=${RELEASE_KEY_SHA256:-}
[ -f "$ROOT/SHA256SUMS" ] || { echo "missing SHA256SUMS" >&2; exit 2; }
(
  cd "$ROOT"
  sha256sum --check --strict SHA256SUMS
)
if [ -f "$ROOT/SHA256SUMS.sig" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required for signature verification" >&2; exit 2; }
  KEY="$ROOT/release-public-key.pem"
  TRUST=untrusted
  if [ -n "$PINNED_KEY" ]; then
    [ -f "$PINNED_KEY" ] || { echo "pinned public key is unavailable" >&2; exit 2; }
    cmp -s "$PINNED_KEY" "$KEY" || { echo "bundle key differs from externally pinned key" >&2; exit 2; }
    KEY="$PINNED_KEY"
    TRUST=trusted_pinned_key
  elif [ -n "$PINNED_FINGERPRINT" ]; then
    ACTUAL=$(sha256sum "$KEY" | cut -d' ' -f1)
    [ "$ACTUAL" = "$PINNED_FINGERPRINT" ] || { echo "bundle key fingerprint differs from external pin" >&2; exit 2; }
    TRUST=trusted_pinned_fingerprint
  fi
  openssl pkeyutl -verify -rawin -pubin -inkey "$KEY" -in "$ROOT/SHA256SUMS" -sigfile "$ROOT/SHA256SUMS.sig" >/dev/null
  echo "signature=valid trust=$TRUST"
else
  echo "signature=absent trust=unsigned"
fi
'''


def _generated_image_loader() -> str:
    """Runtime loader for strict OCI archives carrying a standard ref.name tag."""
    return r'''#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

class ImageError(Exception):
    pass

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def parse_manifest(path: Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageError(f"无法读取镜像清单：{exc}") from exc
    if not isinstance(obj, dict) or obj.get("schema_version") != "resolver-identity-role-image-lock-v1":
        raise ImageError("镜像清单 schema_version 不受支持")
    entries = obj.get("images")
    if not isinstance(entries, list) or not entries:
        raise ImageError("镜像清单 images 必须是非空数组")
    parsed = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ImageError("镜像清单条目必须是对象")
        filename, checksum = entry.get("archive"), entry.get("archive_sha256")
        reference, import_reference, digest = entry.get("reference"), entry.get("import_reference"), entry.get("digest")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ImageError("归档文件名必须是单一安全文件名")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ImageError(f"归档校验值不合法：{filename}")
        if not isinstance(reference, str) or not isinstance(digest, str) or not reference.endswith("@" + digest):
            raise ImageError(f"摘要引用不合法：{filename}")
        repository = reference.split("@", 1)[0]
        expected_import = f"{repository}:ri-{digest.split(':', 1)[1][:16]}"
        if import_reference != expected_import:
            raise ImageError(f"OCI 导入引用不合法：{filename}")
        parsed.append((path.parent / filename, checksum, reference, import_reference))
    return parsed

def inspect_exact(reference: str) -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{json .RepoTags}}"],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        tags = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise ImageError(f"docker inspect 返回不可解析：{exc}") from exc
    if not isinstance(tags, list) or reference not in tags:
        raise ImageError(f"加载后未找到 OCI ref.name 指定的精确镜像：{reference}")

def main() -> int:
    parser = argparse.ArgumentParser(description="严格校验并加载离线 OCI 镜像")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        entries = parse_manifest(args.directory.resolve() / "image-lock.json")
        for archive, expected, _, _ in entries:
            if not archive.is_file() or archive.is_symlink() or sha256(archive) != expected:
                raise ImageError(f"归档校验失败：{archive.name}")
        if args.verify_only:
            return 0
        subprocess.run(["docker", "version"], check=True, stdout=subprocess.DEVNULL)
        for archive, _, reference, import_reference in entries:
            subprocess.run(["docker", "load", "--input", str(archive)], check=True)
            inspect_exact(import_reference)
            print(f"加载后精确引用校验通过：{import_reference}；发布摘要：{reference}")
        return 0
    except (ImageError, OSError, subprocess.CalledProcessError) as exc:
        print(f"错误代码：IMG002\n原因：{exc}\n建议：停止安装并重新取得受信离线镜像。", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
'''


def _spdx(name: str, version: str, commit: str, images: list[dict[str, str]]) -> dict[str, Any]:
    namespace_seed = hashlib.sha256(f"{name}\0{version}\0{commit}".encode()).hexdigest()
    packages = []
    relationships = []
    for index, image in enumerate(images, 1):
        package_id = f"SPDXRef-Image-{index}"
        packages.append(
            {
                "SPDXID": package_id,
                "name": image["key"],
                "versionInfo": image["digest"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:oci/{image['key']}@{image['digest'].split(':', 1)[1]}",
                    }
                ],
                "checksums": [{"algorithm": "SHA256", "checksumValue": image["digest"].split(":", 1)[1]}],
            }
        )
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id})
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://resolver-identity.invalid/spdx/{namespace_seed}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: build_domain_center_site_bundle.py"]},
        "packages": packages,
        "relationships": relationships,
    }


def _cyclonedx(name: str, version: str, commit: str, images: list[dict[str, str]]) -> dict[str, Any]:
    serial = hashlib.sha256(f"{name}\0{version}\0{commit}".encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "serialNumber": f"urn:uuid:{serial[0:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": "1970-01-01T00:00:00Z",
            "component": {"type": "application", "name": name, "version": version, "properties": [{"name": "source.git.commit", "value": commit}]},
            "tools": {"components": [{"type": "application", "name": "build_domain_center_site_bundle.py"}]},
        },
        "components": [
            {
                "type": "container",
                "name": image["key"],
                "version": image["digest"],
                "purl": f"pkg:oci/{image['key']}@{image['digest'].split(':', 1)[1]}",
                "hashes": [{"alg": "SHA-256", "content": image["digest"].split(":", 1)[1]}],
            }
            for image in images
        ],
    }


def _tar_reproducible(source: Path, destination: Path) -> None:
    source.chmod(0o755)
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted([source, *source.rglob("*")]):
                    relative = PurePosixPath(source.name) / PurePosixPath(path.relative_to(source).as_posix())
                    info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    info.mode = 0o755 if path.is_dir() or (path.is_file() and path.stat().st_mode & 0o111) else 0o644
                    if path.is_file():
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        archive.addfile(info)


def _openssl_public_key(key: Path, public_key: Path) -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise BundleError("an Ed25519 signing key was supplied but openssl is unavailable")
    if not key.is_file() or key.is_symlink():
        raise BundleError("signing key must be an external regular PEM file")
    mode = stat.S_IMODE(key.stat().st_mode)
    if mode & 0o077:
        raise BundleError("signing key permissions must not grant group/other access")
    private = key.read_bytes()
    if b"PRIVATE KEY" not in private:
        raise BundleError("signing key is not a PEM private key")
    result = subprocess.run(
        [openssl, "pkey", "-in", str(key), "-pubout", "-out", str(public_key)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or b"ED25519" not in subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-text", "-noout"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.upper():
        raise BundleError("signing key must be a valid Ed25519 PEM")
    return openssl


def _openssl_sign(key: Path, target: Path, signature: Path, public_key: Path) -> None:
    openssl = _openssl_public_key(key, public_key) if not public_key.exists() else shutil.which("openssl")
    if openssl is None:
        raise BundleError("openssl is unavailable")
    subprocess.run([openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(target), "-out", str(signature)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _prepare_signing_public_key(root: Path, key: Path | None) -> None:
    if key is None:
        return
    _openssl_public_key(key, root / "release-public-key.pem")
    (root / "release-public-key.pem").chmod(0o644)


def _sign_checksums(root: Path, key: Path | None) -> bool:
    if key is None:
        return False
    _openssl_sign(key, root / "SHA256SUMS", root / "SHA256SUMS.sig", root / "release-public-key.pem")
    (root / "SHA256SUMS.sig").chmod(0o644)
    return True


def _scan_output(root: Path) -> None:
    policy_source_allowed = {
        PurePosixPath("product-kit/common/lifecycle.py"),
        PurePosixPath("product-kit/common/load_images.py"),
        PurePosixPath("product-kit/management/nornctl.sh"),
        PurePosixPath("product-kit/management/publish-norn.sh"),
        PurePosixPath("product-kit/management/registry-tool.sh"),
        PurePosixPath("product-kit/norn-a/docker-compose.yml"),
        PurePosixPath("product-kit/norn-b/docker-compose.yml"),
    }
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BundleError(f"delivery output contains a symlink: {path.relative_to(root)}")
        if not path.is_file() or path.suffix == ".tar" or path.name.endswith(".tar.gz"):
            continue
        data = path.read_bytes()
        if SECRET_BYTES_RE.search(data):
            raise BundleError(f"delivery output contains private credential material: {path.relative_to(root)}")
        for pattern, reason in FORBIDDEN_OUTPUT_RE:
            if pattern.search(data):
                relative = PurePosixPath(path.relative_to(root).as_posix())
                if pattern.pattern == rb"127\.0\.0\.1" and any(relative.parts[-len(item.parts):] == item.parts for item in policy_source_allowed):
                    continue
                raise BundleError(f"delivery output contains {reason}: {path.relative_to(root)}")


def _render_pdfs(product_kit: Path, output: Path, image: str | None) -> tuple[bool, str]:
    documents = sorted((product_kit / "documents").glob("*.md")) if (product_kit / "documents").is_dir() else []
    if not documents:
        return False, "PDF_BLOCKED: product-kit/documents contains no Markdown inputs"
    if image is None or IMAGE_REF_RE.fullmatch(image) is None or image.startswith("127.0.0.1"):
        return False, "PDF_BLOCKED: a non-loopback digest-pinned offline PDF builder image was not supplied"
    runtime = shutil.which("docker") or shutil.which("podman")
    if runtime is None:
        return False, "PDF_BLOCKED: Docker/Podman is unavailable"
    inspect = subprocess.run([runtime, "image", "inspect", image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if inspect.returncode != 0:
        return False, "PDF_BLOCKED: fixed PDF builder image is not present in the offline runtime"
    output.mkdir(exist_ok=True)
    for document in documents:
        result = subprocess.run(
            [runtime, "run", "--rm", "--network=none", "--pull=never", "--read-only", "-e", "SOURCE_DATE_EPOCH=0", "-v", f"{document.resolve()}:/input.md:ro", "-v", f"{output.resolve()}:/output", image, "/input.md", "-o", f"/output/{document.stem}.pdf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0 or not (output / f"{document.stem}.pdf").is_file():
            shutil.rmtree(output, ignore_errors=True)
            return False, f"PDF_BLOCKED: fixed offline builder failed for {document.name}"
    return True, "generated by fixed digest-pinned external container with network disabled"


def _verify_checksum_file(root: Path, checksum_path: Path, ignored: set[str] | None = None) -> None:
    ignored = ignored or set()
    expected: dict[str, str] = {}
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise BundleError(f"cannot read {checksum_path}: {error}") from error
    for line in lines:
        if not re.fullmatch(r"[0-9a-f]{64}  [^\r\n]+", line):
            raise BundleError(f"malformed checksum line in {checksum_path}")
        digest, name = line.split("  ", 1)
        normalized = _safe_relative(name, "checksum").as_posix()
        if normalized in expected:
            raise BundleError(f"duplicate checksum entry: {normalized}")
        expected[normalized] = digest
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path != checksum_path and path.relative_to(root).as_posix() not in ignored
    }
    if set(expected) != actual:
        raise BundleError(f"checksum file set mismatch; missing={sorted(actual-set(expected))}, extra={sorted(set(expected)-actual)}")
    for name, digest in expected.items():
        if _sha256(root / name) != digest:
            raise BundleError(f"checksum mismatch: {name}")


def _verify_signature(root: Path, trusted_public_key: Path | None = None, trusted_fingerprint: str | None = None) -> dict[str, Any]:
    signature = root / "SHA256SUMS.sig"
    bundled_public = root / "release-public-key.pem"
    if not signature.exists() and not bundled_public.exists():
        if trusted_public_key is not None or trusted_fingerprint is not None:
            raise BundleError("a trust pin was supplied but the delivery is unsigned")
        return {"signed": False, "signature_valid": False, "trust": "unsigned"}
    if not signature.is_file() or not bundled_public.is_file() or signature.is_symlink() or bundled_public.is_symlink():
        raise BundleError("signature output is incomplete")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise BundleError("openssl is required to verify the supplied Ed25519 signature")
    verification_key = bundled_public
    trust = "self_signed/untrusted"
    if trusted_public_key is not None:
        if not trusted_public_key.is_file() or trusted_public_key.is_symlink():
            raise BundleError("externally pinned public key must be a regular file")
        if trusted_public_key.read_bytes() != bundled_public.read_bytes():
            raise BundleError("bundle public key does not match externally pinned public key")
        verification_key = trusted_public_key
        trust = "trusted_pinned_key"
    if trusted_fingerprint is not None:
        if re.fullmatch(r"[0-9a-f]{64}", trusted_fingerprint) is None:
            raise BundleError("trusted public key fingerprint must be lowercase SHA-256")
        if hashlib.sha256(bundled_public.read_bytes()).hexdigest() != trusted_fingerprint:
            raise BundleError("bundle public key does not match externally pinned fingerprint")
        trust = "trusted_pinned_fingerprint" if trusted_public_key is None else "trusted_pinned_key_and_fingerprint"
    result = subprocess.run([openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(verification_key), "-in", str(root / "SHA256SUMS"), "-sigfile", str(signature)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise BundleError("Ed25519 signature verification failed")
    return {"signed": True, "signature_valid": True, "trust": trust}


def verify_delivery(
    root: Path,
    *,
    allow_blocked: bool = False,
    trusted_public_key: Path | None = None,
    trusted_fingerprint: str | None = None,
) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise BundleError("delivery path must be a regular directory")
    signature_files = {"SHA256SUMS.sig"}
    _verify_checksum_file(root, root / "SHA256SUMS", signature_files if (root / "SHA256SUMS.sig").exists() else set())
    signature_result = _verify_signature(root, trusted_public_key, trusted_fingerprint)
    signed = signature_result["signed"]
    evidence = _object(load_json(root / "证据.json", "delivery evidence"), "delivery evidence")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise BundleError("delivery evidence schema is invalid")
    if evidence.get("host_count") != 6:
        raise BundleError("delivery evidence does not describe six hosts")
    if bool(evidence.get("signing", {}).get("signed")) != signed:
        raise BundleError("delivery evidence signing state is inconsistent")
    if evidence.get("real_server_deployed") is not False or evidence.get("production_traffic_enabled") is not False:
        raise BundleError("bundle evidence must not claim real deployment or production traffic")
    checks = _object(evidence.get("checks"), "delivery evidence checks")
    missing_checks = REQUIRED_EXTERNAL_ACCEPTANCE_IDS - set(checks)
    if missing_checks:
        raise BundleError("delivery evidence omits mandatory acceptance IDs: " + ", ".join(sorted(missing_checks)))
    for check_id, raw_check in checks.items():
        check = _object(raw_check, f"delivery evidence checks.{check_id}")
        status = check.get("status")
        status_zh = check.get("status_zh")
        if status not in STATUS_VOCABULARY or status_zh not in STATUS_VOCABULARY[status]:
            raise BundleError(f"delivery evidence check has an invalid status: {check_id}")
    mandatory_passed = all(_status_passed(checks[item]["status"]) for item in REQUIRED_EXTERNAL_ACCEPTANCE_IDS)
    all_checks_passed = mandatory_passed and all(_status_passed(item["status"]) for item in checks.values())
    if evidence.get("delivery_ready") is not (all_checks_passed and not evidence.get("blockers")):
        raise BundleError("delivery_ready is inconsistent with mandatory acceptance checks and blockers")
    archives = sorted((root / "03-主机包").glob("*.tar.gz"))
    if len(archives) != 6:
        raise BundleError("delivery must contain exactly six host archives")
    host_records = evidence.get("hosts")
    if not isinstance(host_records, list) or len(host_records) != 6:
        raise BundleError("delivery evidence must contain exactly six host records")
    record_by_archive: dict[str, dict[str, Any]] = {}
    role_counts = {role: 0 for role in ROLE_COUNTS}
    for index, raw_record in enumerate(host_records):
        record = _object(raw_record, f"delivery evidence hosts[{index}]")
        _exact_keys(record, {"hostname", "role", "archive", "sha256", "images"}, set(), f"delivery evidence hosts[{index}]")
        role = _text(record["role"], f"delivery evidence hosts[{index}].role")
        if role not in role_counts:
            raise BundleError("delivery evidence contains an unknown host role")
        role_counts[role] += 1
        archive_name = _safe_relative(_text(record["archive"], "host archive evidence path"), "host archive evidence path").as_posix()
        if archive_name in record_by_archive:
            raise BundleError("delivery evidence repeats a host archive")
        record_by_archive[archive_name] = record
    if role_counts != ROLE_COUNTS:
        raise BundleError(f"delivery evidence role counts must equal {ROLE_COUNTS}")
    actual_archive_names = {path.relative_to(root).as_posix() for path in archives}
    if set(record_by_archive) != actual_archive_names:
        raise BundleError("delivery evidence host archive set is inconsistent")
    for archive_path in archives:
        archive_relative = archive_path.relative_to(root).as_posix()
        record = record_by_archive[archive_relative]
        if record["sha256"] != _sha256(archive_path):
            raise BundleError(f"delivery evidence digest mismatch: {archive_relative}")
        hostname = _text(record["hostname"], "host evidence hostname", HOST_RE)
        role = record["role"]
        expected_image_digests = record["images"]
        if not isinstance(expected_image_digests, list) or len(expected_image_digests) != len(ROLE_IMAGES[role]):
            raise BundleError(f"delivery evidence image list is invalid: {hostname}")
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                names: set[str] = set()
                files: dict[str, bytes] = {}
                for member in archive:
                    name = _safe_relative(member.name, f"host archive {archive_path.name}").as_posix()
                    if name in names or member.issym() or member.islnk():
                        raise BundleError(f"unsafe/duplicate host archive member: {name}")
                    names.add(name)
                    if member.isfile():
                        handle = archive.extractfile(member)
                        if handle is None:
                            raise BundleError(f"unreadable host archive member: {name}")
                        files[name] = handle.read()
                checksum_names = [name for name in files if name.endswith("/SHA256SUMS")]
                if len(checksum_names) != 1:
                    raise BundleError(f"host archive {archive_path.name} has no unique checksum file")
                prefix = checksum_names[0][: -len("SHA256SUMS")]
                if prefix != f"{hostname}/":
                    raise BundleError(f"host archive {archive_path.name} has the wrong root directory")
                metadata_name = prefix + "metadata/host.json"
                lock_name = prefix + "images/image-lock.json"
                metadata = _object(load_json_bytes(files.get(metadata_name, b""), metadata_name), metadata_name)
                if metadata.get("expected_host") != hostname or metadata.get("hostname") != hostname or metadata.get("role") != role:
                    raise BundleError(f"host archive metadata mismatch: {hostname}")
                lock = _object(load_json_bytes(files.get(lock_name, b""), lock_name), lock_name)
                if lock.get("schema_version") != LOCK_SCHEMA or lock.get("hostname") != hostname or lock.get("role") != role:
                    raise BundleError(f"host archive image lock metadata mismatch: {hostname}")
                required_members = {
                    prefix + "README-请先阅读.txt",
                    prefix + "expected-host.json",
                    prefix + "wizard.py",
                    prefix + f"product-kit/{role}/docker-compose.yml",
                    prefix + "product-kit/common/lifecycle.py",
                    prefix + "product-kit/common/load_images.py",
                    prefix + "product-kit/common/role_entry.py",
                    *{prefix + name for name in CHINESE_ENTRY_POINTS},
                    *{prefix + f"scripts/{name}.sh" for name in ASCII_ENTRY_POINTS},
                }
                missing_members = sorted(required_members - set(files))
                if missing_members:
                    raise BundleError(f"host archive is not standalone; missing={missing_members}")
                expected_host_name = prefix + "expected-host.json"
                expected_host = _object(load_json_bytes(files.get(expected_host_name, b""), expected_host_name), expected_host_name)
                if expected_host != metadata:
                    raise BundleError(f"host archive expected-host metadata mismatch: {hostname}")
                lock_images = _array(lock.get("images"), f"{hostname} image lock images")
                if len(lock_images) != len(ROLE_IMAGES[role]):
                    raise BundleError(f"host archive has the wrong role-local image count: {hostname}")
                lock_keys: list[str] = []
                lock_digests: list[str] = []
                for lock_index, raw_image in enumerate(lock_images):
                    image = _object(raw_image, f"{hostname} image lock[{lock_index}]")
                    _exact_keys(image, {"key", "reference", "import_reference", "digest", "archive", "archive_sha256"}, set(), f"{hostname} image lock[{lock_index}]")
                    key = _text(image["key"], f"{hostname} image key")
                    reference = _text(image["reference"], f"{hostname} image reference")
                    import_reference = _text(image["import_reference"], f"{hostname} image import reference")
                    digest = _text(image["digest"], f"{hostname} image digest")
                    if key not in ROLE_IMAGES[role] or IMAGE_REF_RE.fullmatch(reference) is None or not reference.endswith("@" + digest):
                        raise BundleError(f"host archive has an invalid image lock: {hostname}")
                    if import_reference != _import_reference(reference.split("@", 1)[0], digest):
                        raise BundleError(f"host archive has invalid OCI import reference metadata: {hostname}")
                    archive_member = prefix + "images/" + _safe_relative(_text(image["archive"], "image archive path"), "image archive path").as_posix()
                    image_data = files.get(archive_member)
                    if image_data is None or hashlib.sha256(image_data).hexdigest() != image["archive_sha256"]:
                        raise BundleError(f"host archive image tar digest mismatch: {hostname}/{key}")
                    lock_keys.append(key)
                    lock_digests.append(digest)
                if tuple(lock_keys) != ROLE_IMAGES[role] or lock_digests != expected_image_digests:
                    raise BundleError(f"host archive role-local image lock is inconsistent: {hostname}")
                listed: dict[str, str] = {}
                for line in files[checksum_names[0]].decode("utf-8").splitlines():
                    if not re.fullmatch(r"[0-9a-f]{64}  [^\r\n]+", line):
                        raise BundleError(f"host archive {archive_path.name} has malformed checksums")
                    digest, relative = line.split("  ", 1)
                    if relative in listed:
                        raise BundleError(f"host archive {archive_path.name} repeats checksum path")
                    listed[relative] = digest
                actual = {name[len(prefix):] for name in files if name != checksum_names[0]}
                if set(listed) != actual:
                    raise BundleError(f"host archive {archive_path.name} checksum file set mismatch")
                for relative, digest in listed.items():
                    if hashlib.sha256(files[prefix + relative]).hexdigest() != digest:
                        raise BundleError(f"host archive {archive_path.name} checksum mismatch: {relative}")
        except (OSError, UnicodeError, tarfile.TarError) as error:
            raise BundleError(f"invalid host archive {archive_path}: {error}") from error
    _scan_output(root)
    blockers = evidence.get("blockers")
    if not isinstance(blockers, list) or not all(isinstance(item, str) for item in blockers):
        raise BundleError("delivery evidence blockers must be an array of strings")
    if blockers and not allow_blocked:
        raise BundleError("delivery verifies structurally but remains blocked: " + "; ".join(blockers))
    blocked = bool(blockers) or any(not _status_passed(item["status"]) for item in checks.values())
    if blocked and not allow_blocked:
        raise BundleError("delivery verifies structurally but has non-passed checks")
    return {"verified": True, **signature_result, "blocked": blocked, "blockers": blockers}


def build_delivery(
    site_path: Path,
    release_path: Path,
    product_kit: Path,
    output_parent: Path,
    signing_key: Path | None,
    pdf_builder_image: str | None,
    *,
    force: bool = False,
) -> Path:
    validated = validate_inputs(site_path, release_path)
    def _inventory_tree(path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for member in path.rglob("*"):
            relative = member.relative_to(path).as_posix()
            if member.is_symlink():
                result[relative] = "symlink"
            elif member.is_dir():
                result[relative + "/"] = f"directory:{stat.S_IMODE(member.stat().st_mode):04o}"
            elif member.is_file():
                result[relative] = f"file:{stat.S_IMODE(member.stat().st_mode):04o}:{_sha256(member)}"
        return result

    if not product_kit.is_dir() or product_kit.is_symlink():
        raise BundleError("product-kit must be an existing regular directory")
    product_kit_before = _inventory_tree(product_kit)
    delivery_name = f"{DELIVERY_PREFIX}_{validated['version']}"
    destination = output_parent / delivery_name
    if destination.exists():
        if not force:
            raise BundleError(f"output already exists: {destination}; use --force only for a generated delivery")
        marker = destination / ".domain-center-easy-bundle"
        if not marker.is_file() or marker.read_text(encoding="ascii") != SCHEMA + "\n":
            raise BundleError("refusing to replace a directory without the managed bundle marker")
    output_parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    output_parent.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="domain-center-easy-", dir=output_parent) as temporary:
        root = Path(temporary) / delivery_name
        _mkdir(root)
        for directory in TOP_LEVEL_DIRECTORIES:
            _mkdir(root / directory)
        _write_text(root / ".domain-center-easy-bundle", SCHEMA + "\n")
        host_archives = root / "03-主机包"
        all_image_records = [
            {"key": key, "digest": image["digest"], "reference": image["reference"], "archive_sha256": image["archive_sha256"]}
            for key, image in sorted(validated["images"].items())
        ]
        host_evidence = []
        with tempfile.TemporaryDirectory(prefix="host-build-", dir=output_parent) as host_temporary:
            build_root = Path(host_temporary)
            for host in validated["hosts"]:
                hostname, role = host["hostname"], host["role"]
                host_root = build_root / hostname
                product_root = host_root / "product-kit"
                template_target = product_root / role
                lock_images = []
                for key in ROLE_IMAGES[role]:
                    image = validated["images"][key]
                    lock_images.append({"key": key, "reference": image["reference"], "import_reference": image["import_reference"], "digest": image["digest"], "archive": f"{key}.oci.tar", "archive_sha256": image["archive_sha256"]})
                replacements = {
                    "{{HOSTNAME}}": hostname,
                    "{{ROLE}}": role,
                    "{{VERSION}}": validated["version"],
                    "{{SOURCE_COMMIT}}": validated["source_commit"],
                }
                for image in lock_images:
                    replacements[f"{{{{IMAGE_{image['key'].upper().replace('-', '_')}}}}}"] = image["reference"]
                _copy_template(product_kit / ROLE_TEMPLATE[role], template_target, replacements)
                common_target = product_root / "common"
                _mkdir(common_target)
                for common_name in ("lifecycle.py", "load_images.py", "role_entry.py"):
                    common_source = product_kit / "common" / common_name
                    if not common_source.is_file() or common_source.is_symlink():
                        raise BundleError(f"required package runtime is unavailable: {common_source}")
                    if common_name == "load_images.py":
                        _write_text(common_target / common_name, _generated_image_loader())
                    else:
                        shutil.copy2(common_source, common_target / common_name)
                        (common_target / common_name).chmod(0o644)
                wizard_source = Path(__file__).resolve().parents[1] / "installer" / "wizard.py"
                if not wizard_source.is_file() or wizard_source.is_symlink():
                    raise BundleError(f"required package wizard is unavailable: {wizard_source}")
                shutil.copy2(wizard_source, host_root / "wizard.py")
                (host_root / "wizard.py").chmod(0o644)
                image_dir = host_root / "images"
                _mkdir(image_dir)
                for image in lock_images:
                    shutil.copyfile(validated["images"][image["key"]]["archive"], image_dir / image["archive"])
                    (image_dir / image["archive"]).chmod(0o644)
                lock = {"schema_version": LOCK_SCHEMA, "hostname": hostname, "role": role, "images": lock_images}
                _write_json(image_dir / "image-lock.json", lock)
                metadata = host_root / "metadata"
                _mkdir(metadata)
                host_metadata = {"schema_version": SCHEMA, "expected_host": hostname, "hostname": hostname, "role": role, "version": validated["version"], "source_commit": validated["source_commit"], "release_manifest_sha256": validated["release_manifest_sha256"], "platform": validated["platform"]}
                _write_json(host_root / "expected-host.json", host_metadata)
                _write_json(metadata / "host.json", host_metadata)
                _write_json(metadata / "sbom.spdx.json", _spdx(hostname, validated["version"], validated["source_commit"], lock_images))
                _write_json(metadata / "sbom.cdx.json", _cyclonedx(hostname, validated["version"], validated["source_commit"], lock_images))
                _write_text(host_root / "README-请先阅读.txt", _host_readme(hostname, role))
                _write_host_entry_points(host_root, role, hostname)
                _scan_output(host_root)
                _write_checksums(host_root, host_root / "SHA256SUMS")
                archive_path = host_archives / f"{hostname}.tar.gz"
                _tar_reproducible(host_root, archive_path)
                archive_path.chmod(0o644)
                host_evidence.append({"hostname": hostname, "role": role, "archive": f"03-主机包/{archive_path.name}", "sha256": _sha256(archive_path), "images": [item["digest"] for item in lock_images]})
        sbom_dir = root / "04-软件物料清单"
        _write_json(sbom_dir / "site.spdx.json", _spdx(delivery_name, validated["version"], validated["source_commit"], all_image_records))
        _write_json(sbom_dir / "site.cdx.json", _cyclonedx(delivery_name, validated["version"], validated["source_commit"], all_image_records))
        pdf_ready, pdf_detail = _render_pdfs(product_kit, root / "05-PDF手册", pdf_builder_image)
        blockers = []
        checks: dict[str, dict[str, str]] = dict(validated["external_requirements"])
        if signing_key is None:
            blockers.append("SIGNING_BLOCKED: no externally supplied Ed25519 PEM was provided")
            checks["bundle_signing"] = {"status": "blocked", "status_zh": "阻断", "reason_zh": "未提供外部 Ed25519 签名密钥"}
        if not pdf_ready:
            blockers.append(pdf_detail)
            checks["pdf_manual"] = {"status": "blocked", "status_zh": "阻断", "reason_zh": pdf_detail}
        evidence = {
            "schema_version": EVIDENCE_SCHEMA,
            "version": validated["version"],
            "source_commit": validated["source_commit"],
            "source_release_manifest_sha256": validated["release_manifest_sha256"],
            "host_count": 6,
            "hosts": host_evidence,
            "oci_validation": {"passed": True, "strict_single_platform": validated["platform"], "images": all_image_records},
            "sbom": {"spdx_json": "04-软件物料清单/site.spdx.json", "cyclonedx_json": "04-软件物料清单/site.cdx.json"},
            "signing": {"signed": signing_key is not None, "algorithm": "Ed25519", "implementation": "openssl" if signing_key is not None else None},
            "pdf": {"ready": pdf_ready, "builder_image": pdf_builder_image, "detail": pdf_detail},
            "runtime_policy": {"offline_only": True, "runtime_pulls_forbidden": True, "latest_forbidden": True, "loopback_image_references_forbidden": True},
            "topology_note": "R2/R3 configuration has no Wrapper service. The shared Rust image may contain the Wrapper binary; configuration intentionally does not make it runnable.",
            "blockers": blockers,
            "checks": checks,
            "delivery_ready": not blockers and all(_status_passed(item["status"]) for item in checks.values()),
            "real_server_deployed": False,
            "production_traffic_enabled": False,
            "verification_command": "./recipient-verify.sh /offline/path/to/pinned-release-public-key.pem",
        }
        _write_json(root / "12-验收证据" / "证据.json", evidence)
        shutil.copyfile(root / "12-验收证据" / "证据.json", root / "证据.json")
        (root / "证据.json").chmod(0o644)
        _write_text(root / "00-开始" / "验证命令.txt", "./recipient-verify.sh /离线路径/已固定-release-public-key.pem\n")
        _write_text(root / "recipient-verify.sh", _recipient_verify_script(), 0o755)
        _prepare_signing_public_key(root, signing_key)
        _scan_output(root)
        checksum_exclusions = {root / "SHA256SUMS.sig"}
        _write_checksums(root, root / "SHA256SUMS", checksum_exclusions)
        _sign_checksums(root, signing_key)
        if _inventory_tree(product_kit) != product_kit_before:
            raise BundleError("product-kit changed during generation; generator never mutates product-kit")
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(root, destination)
    return destination


def _make_test_oci(path: Path, digest_out: dict[str, str], repository: str | None = None) -> None:
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode="w") as layer:
        data = b"offline\n"
        info = tarfile.TarInfo("payload.txt")
        info.size = len(data)
        info.mtime = 0
        layer.addfile(info, io.BytesIO(data))
    layer_data = layer_stream.getvalue()
    layer_digest = hashlib.sha256(layer_data).hexdigest()
    config_data = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]}}, separators=(",", ":"), sort_keys=True).encode()
    config_digest = hashlib.sha256(config_data).hexdigest()
    manifest_data = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {"mediaType": OCI_CONFIG, "digest": f"sha256:{config_digest}", "size": len(config_data)}, "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": f"sha256:{layer_digest}", "size": len(layer_data)}]}, separators=(",", ":"), sort_keys=True).encode()
    manifest_digest = hashlib.sha256(manifest_data).hexdigest()
    index_data = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": f"sha256:{manifest_digest}",
                    "size": len(manifest_data),
                    "platform": {"os": "linux", "architecture": "amd64"},
                    **({"annotations": {OCI_REF_ANNOTATION: _import_reference(repository, f"sha256:{manifest_digest}")}} if repository else {}),
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": index_data, f"blobs/sha256/{config_digest}": config_data, f"blobs/sha256/{layer_digest}": layer_data, f"blobs/sha256/{manifest_digest}": manifest_data}
    with tarfile.open(path, "w") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    digest_out["digest"] = manifest_digest


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="domain-center-self-test-") as temporary:
        root = Path(temporary)
        oci = root / "image.tar"
        digest: dict[str, str] = {}
        _make_test_oci(oci, digest, "registry.internal/example/test")
        validate_oci_archive(oci, f"sha256:{digest['digest']}", {"os": "linux", "architecture": "amd64"})
        try:
            load_json_bytes(b'{"a":1,"a":2}', "duplicate test")
        except BundleError:
            pass
        else:
            raise AssertionError("duplicate JSON key was accepted")
        release = {"version": "test-1", "git_commit": "a" * 40, "images": {key: f"127.0.0.1:5000/example/{key}@sha256:{digest['digest']}" for key in EXPECTED_IMAGE_KEYS}}
        release_path = root / "release.json"
        _write_json(release_path, release)
        site = {"schema_version": SCHEMA, "release": {"version": "test-1", "source_commit": "a" * 40, "manifest_sha256": _sha256(release_path)}, "platform": {"os": "linux", "architecture": "amd64"}, "hosts": [{"hostname": "mgmt-01", "role": "management"}, {"hostname": "node-a-01", "role": "norn-a"}, {"hostname": "node-b-01", "role": "norn-b"}, {"hostname": "resolver-r1", "role": "r1"}, {"hostname": "resolver-r2", "role": "r2"}, {"hostname": "resolver-r3", "role": "r3"}], "images": {key: {"archive": str(oci), "repository": "registry.internal/example/test"} for key in EXPECTED_IMAGE_KEYS}, "external_requirements": {requirement_id: {"status": "not_run", "status_zh": "未运行", "blocked_by": "external_approval"} for requirement_id in REQUIRED_EXTERNAL_ACCEPTANCE_IDS}}
        site_path = root / "site.json"
        _write_json(site_path, site)
        kit = root / "product-kit"
        source_kit = Path(__file__).resolve().parents[1] / "deploy" / "easy-install" / "product-kit"
        shutil.copytree(source_kit, kit)
        destination = build_delivery(site_path, release_path, kit, root / "out", None, None)
        first_hashes = {path.relative_to(destination).as_posix(): _sha256(path) for path in destination.rglob("*") if path.is_file()}
        verify_delivery(destination, allow_blocked=True)
        destination = build_delivery(site_path, release_path, kit, root / "out", None, None, force=True)
        second_hashes = {path.relative_to(destination).as_posix(): _sha256(path) for path in destination.rglob("*") if path.is_file()}
        if first_hashes != second_hashes:
            raise AssertionError("delivery generation is not deterministic")
        openssl = shutil.which("openssl")
        if openssl is not None:
            key = root / "signing-key.pem"
            subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            key.chmod(0o600)
            destination = build_delivery(site_path, release_path, kit, root / "out", key, None, force=True)
            signed_result = verify_delivery(destination, allow_blocked=True)
            if not signed_result["signed"]:
                raise AssertionError("signed delivery did not verify as signed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "build"):
        child = subparsers.add_parser(name)
        child.add_argument("--site-manifest", "--manifest", type=Path, required=True)
        child.add_argument("--release-manifest", type=Path, required=True)
        if name == "build":
            child.add_argument("--product-kit", type=Path, required=True)
            child.add_argument("--output", "--output-parent", dest="output", type=Path, required=True, help="parent directory; creates resolver-identity-domain-center-easy-install-<version>")
            child.add_argument("--signing-key", type=Path, help="external Ed25519 private-key PEM; never copied")
            child.add_argument("--pdf-builder-image", help="locally present, digest-pinned Pandoc-compatible image")
            child.add_argument("--force", action="store_true")
    verify = subparsers.add_parser("verify")
    verify.add_argument("delivery", type=Path)
    verify.add_argument("--allow-blocked", action="store_true", help="return success for structurally valid unsigned/PDF-blocked output")
    trust = verify.add_mutually_exclusive_group()
    trust.add_argument("--trusted-public-key", type=Path, help="externally distributed pinned Ed25519 public-key PEM")
    trust.add_argument("--trusted-key-sha256", help="externally pinned lowercase SHA-256 of release-public-key.pem")
    subparsers.add_parser("self-test")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "validate":
            validated = validate_inputs(arguments.site_manifest.resolve(), arguments.release_manifest.resolve())
            print(json.dumps({"valid": True, "version": validated["version"], "source_commit": validated["source_commit"], "host_count": len(validated["hosts"]), "image_count": len(validated["images"])}, sort_keys=True))
        elif arguments.command == "build":
            destination = build_delivery(arguments.site_manifest.resolve(), arguments.release_manifest.resolve(), arguments.product_kit.resolve(), arguments.output.resolve(), arguments.signing_key.resolve() if arguments.signing_key else None, arguments.pdf_builder_image, force=arguments.force)
            evidence = load_json(destination / "证据.json", "delivery evidence")
            print(json.dumps({"built": True, "delivery": str(destination), "delivery_ready": evidence["delivery_ready"], "blockers": evidence["blockers"]}, ensure_ascii=False, sort_keys=True))
        elif arguments.command == "verify":
            print(json.dumps(verify_delivery(
                arguments.delivery.resolve(),
                allow_blocked=arguments.allow_blocked,
                trusted_public_key=arguments.trusted_public_key.resolve() if arguments.trusted_public_key else None,
                trusted_fingerprint=arguments.trusted_key_sha256,
            ), ensure_ascii=False, sort_keys=True))
        else:
            self_test()
            print(json.dumps({"self_test": "passed"}))
    except (BundleError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
