#!/usr/bin/env python3
"""严格校验并加载离线 OCI 镜像；兼容 Docker 传统与 OCI manifest ID 语义。

归档 SHA-256、manifest digest、config digest、服务绑定和确定性本地标签全部由发布锁固定；
加载过程不访问 registry，也不会执行 pull。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


LOCK_SCHEMA_V1 = "resolver-identity-role-image-lock-v1"
LOCK_SCHEMA_V2 = "resolver-identity-role-image-lock-v2"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
REFERENCE_RE = re.compile(r"([^\s@]+)@(sha256:[0-9a-f]{64})")
IMPORT_RE = re.compile(r"([^\s@:]+(?:[:][0-9]+)?(?:/[^\s@:]+)*):ri-([0-9a-f]{16})")


class ImageError(Exception):
    pass


def error(code: str, reason: str, advice: str) -> int:
    print(f"错误代码：{code}\n原因：{reason}\n建议：{advice}", file=sys.stderr)
    return 2


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def image_ids() -> set[str]:
    result = subprocess.run(
        ["docker", "image", "ls", "--no-trunc", "--quiet"], check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return {line.strip() for line in result.stdout.splitlines() if DIGEST_RE.fullmatch(line.strip())}


def remove_images(references: set[str]) -> None:
    for reference in sorted(references):
        subprocess.run(
            ["docker", "image", "rm", "--force", reference], check=False,
            text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def inspect_image(reference: str) -> dict[str, object]:
    result = subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{json .}}"],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        value = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise ImageError(f"docker inspect 返回不可解析：{exc}") from exc
    if not isinstance(value, dict):
        raise ImageError("docker inspect 未返回镜像对象")
    return value


def _safe_name(value: object, description: str) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ImageError(f"{description}必须是单一安全名称")
    return value


def _parse_image(entry: object, archive_ids: set[str], *, legacy: bool) -> dict[str, str]:
    expected = {
        "key", "reference", "import_reference", "digest", "config_digest", "archive", "archive_sha256"
    } if legacy else {
        "id", "archive_id", "reference", "import_reference", "digest", "config_digest"
    }
    if not isinstance(entry, dict) or set(entry) != expected:
        raise ImageError("镜像清单条目字段集合不合法")
    image_id = entry["key"] if legacy else entry["id"]
    archive_id = entry["archive"] if legacy else entry["archive_id"]
    if not isinstance(image_id, str) or not image_id:
        raise ImageError("镜像 ID 不合法")
    if not isinstance(archive_id, str) or archive_id not in archive_ids:
        raise ImageError(f"镜像引用未知归档：{image_id}")
    reference = entry["reference"]
    import_reference = entry["import_reference"]
    digest = entry["digest"]
    config_digest = entry["config_digest"]
    match = REFERENCE_RE.fullmatch(reference) if isinstance(reference, str) else None
    if match is None or match.group(2) != digest or (":late" + "st") in reference.lower() or "localhost" in reference.lower():
        raise ImageError(f"原始 OCI 摘要引用不合法：{image_id}")
    expected_import = f"{match.group(1)}:ri-{digest.split(':', 1)[1][:16]}"
    if not isinstance(import_reference, str) or IMPORT_RE.fullmatch(import_reference) is None or import_reference != expected_import:
        raise ImageError(f"OCI 本地导入标签不合法：{image_id}")
    if not isinstance(config_digest, str) or DIGEST_RE.fullmatch(config_digest) is None:
        raise ImageError(f"OCI config digest 不合法：{image_id}")
    return {
        "id": image_id,
        "archive_id": archive_id,
        "reference": reference,
        "import_reference": import_reference,
        "digest": digest,
        "config_digest": config_digest,
    }


def parse_lock(path: Path) -> dict[str, object]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageError(f"无法读取镜像清单：{exc}") from exc
    if not isinstance(obj, dict):
        raise ImageError("镜像清单必须是对象")
    schema = obj.get("schema_version")
    if schema == LOCK_SCHEMA_V1:
        if set(obj) != {"schema_version", "hostname", "role", "images"}:
            raise ImageError("镜像清单字段集合不合法")
        entries = obj.get("images")
        if not isinstance(entries, list) or not entries:
            raise ImageError("镜像清单 images 必须是非空数组")
        archives: list[dict[str, str]] = []
        archive_ids: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ImageError("镜像清单条目字段集合不合法")
            filename = _safe_name(entry.get("archive"), "归档文件名")
            checksum = entry.get("archive_sha256")
            if filename in archive_ids:
                raise ImageError("归档文件名必须唯一")
            if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                raise ImageError(f"归档校验值不合法：{filename}")
            archive_ids.add(filename)
            archives.append({"id": filename, "archive": filename, "archive_sha256": checksum})
        images = [_parse_image(entry, archive_ids, legacy=True) for entry in entries]
        return {"schema_version": schema, "archives": archives, "images": images, "services": []}
    if schema != LOCK_SCHEMA_V2:
        raise ImageError("镜像清单 schema_version 不受支持")
    if set(obj) != {"schema_version", "hostname", "role", "archives", "images", "services"}:
        raise ImageError("镜像清单字段集合不合法")
    raw_archives = obj.get("archives")
    raw_images = obj.get("images")
    raw_services = obj.get("services")
    if not isinstance(raw_archives, list) or not raw_archives:
        raise ImageError("镜像清单 archives 必须是非空数组")
    if not isinstance(raw_images, list) or not raw_images:
        raise ImageError("镜像清单 images 必须是非空数组")
    if not isinstance(raw_services, list) or not raw_services:
        raise ImageError("镜像清单 services 必须是非空数组")
    archives: list[dict[str, str]] = []
    archive_ids: set[str] = set()
    archive_names: set[str] = set()
    for entry in raw_archives:
        if not isinstance(entry, dict) or set(entry) != {"id", "archive", "archive_sha256"}:
            raise ImageError("归档清单条目字段集合不合法")
        archive_id = _safe_name(entry["id"], "归档 ID")
        filename = _safe_name(entry["archive"], "归档文件名")
        checksum = entry["archive_sha256"]
        if archive_id in archive_ids or filename in archive_names:
            raise ImageError("归档 ID 和文件名必须唯一")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ImageError(f"归档校验值不合法：{filename}")
        archive_ids.add(archive_id)
        archive_names.add(filename)
        archives.append({"id": archive_id, "archive": filename, "archive_sha256": checksum})
    images = [_parse_image(entry, archive_ids, legacy=False) for entry in raw_images]
    image_ids_seen: set[str] = set()
    import_references: set[str] = set()
    for image in images:
        if image["id"] in image_ids_seen or image["import_reference"] in import_references:
            raise ImageError("镜像 ID 和本地导入标签必须唯一")
        image_ids_seen.add(image["id"])
        import_references.add(image["import_reference"])
    services: list[dict[str, str]] = []
    service_names: set[str] = set()
    variables: set[str] = set()
    for entry in raw_services:
        if not isinstance(entry, dict) or set(entry) != {"service", "compose_variable", "image_id"}:
            raise ImageError("服务镜像绑定字段集合不合法")
        service = entry["service"]
        variable = entry["compose_variable"]
        image_id = entry["image_id"]
        if not isinstance(service, str) or not service or service in service_names:
            raise ImageError("服务名必须是唯一非空字符串")
        if not isinstance(variable, str) or re.fullmatch(r"RI_[A-Z0-9_]+_IMAGE", variable) is None or variable in variables:
            raise ImageError("Compose 镜像变量必须是唯一 RI_*_IMAGE 名称")
        if not isinstance(image_id, str) or image_id not in image_ids_seen:
            raise ImageError(f"服务引用未知镜像：{service}")
        service_names.add(service)
        variables.add(variable)
        services.append({"service": service, "compose_variable": variable, "image_id": image_id})
    return {"schema_version": schema, "archives": archives, "images": images, "services": services}


def parse_manifest(path: Path) -> list[tuple[Path, str, str, str, str, str]]:
    """Return archive, archive SHA-256, references, manifest and config digests."""
    lock = parse_lock(path)
    archive_by_id = {entry["id"]: entry for entry in lock["archives"]}
    return [
        (
            path.parent / archive_by_id[image["archive_id"]]["archive"],
            archive_by_id[image["archive_id"]]["archive_sha256"],
            image["reference"],
            image["import_reference"],
            image["digest"],
            image["config_digest"],
        )
        for image in lock["images"]
    ]


def verify_loaded(import_reference: str, digest: str, config_digest: str) -> None:
    image = inspect_image(import_reference)
    image_id = image.get("Id")
    tags = image.get("RepoTags")
    if image_id not in (digest, config_digest):
        raise ImageError(f"加载后镜像 ID 与已校验 OCI digest 不一致：{import_reference}")
    if not isinstance(tags, list) or import_reference not in tags:
        raise ImageError(f"加载后未找到确定性本地标签：{import_reference}")


def main() -> int:
    parser = argparse.ArgumentParser(description="严格校验并加载离线 OCI 镜像")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    imported_tags: set[str] = set()
    loaded_ids: set[str] = set()
    loading_started = False
    try:
        lock_path = args.directory.resolve() / "image-lock.json"
        lock = parse_lock(lock_path)
        archives = {entry["id"]: entry for entry in lock["archives"]}
        images_by_archive: dict[str, list[dict[str, str]]] = {}
        for image in lock["images"]:
            images_by_archive.setdefault(image["archive_id"], []).append(image)
        for archive in archives.values():
            path = lock_path.parent / archive["archive"]
            if not path.is_file() or path.is_symlink() or sha256(path) != archive["archive_sha256"]:
                raise ImageError(f"归档校验失败：{path.name}")
            print(f"归档校验通过：{path.name}")
        if args.verify_only:
            return 0
        subprocess.run(["docker", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        loading_started = True
        for archive_id, images in images_by_archive.items():
            archive = archives[archive_id]
            archive_path = lock_path.parent / archive["archive"]
            missing: list[dict[str, str]] = []
            for image in images:
                try:
                    verify_loaded(image["import_reference"], image["digest"], image["config_digest"])
                except (ImageError, subprocess.CalledProcessError):
                    missing.append(image)
            if missing:
                before_ids = image_ids()
                expected_ids = {value for image in missing for value in (image["digest"], image["config_digest"])}
                if not all(before_ids & {image["digest"], image["config_digest"]} for image in missing):
                    subprocess.run(["docker", "load", "--input", str(archive_path)], check=True)
                after_ids = image_ids()
                loaded_ids.update((after_ids - before_ids) & expected_ids)
                for image in missing:
                    matched_ids = after_ids & {image["digest"], image["config_digest"]}
                    if len(matched_ids) != 1:
                        raise ImageError(
                            f"Docker 加载出镜像 ID {sorted(after_ids - before_ids)}，未唯一匹配锁定 manifest/config digest"
                        )
                    source_id = matched_ids.pop()
                    subprocess.run(["docker", "image", "tag", source_id, image["import_reference"]], check=True)
                    imported_tags.add(image["import_reference"])
            for image in images:
                verify_loaded(image["import_reference"], image["digest"], image["config_digest"])
                print(f"加载校验通过：本地标签 {image['import_reference']}；原始 OCI manifest {image['reference']}")
        return 0
    except (ImageError, OSError, subprocess.CalledProcessError) as exc:
        if loading_started:
            try:
                remove_images(imported_tags | loaded_ids)
            except Exception:
                remove_images(imported_tags)
        if isinstance(exc, FileNotFoundError):
            return error("IMG003", f"所需命令或文件不存在：{exc}", "安装 Docker 并重新复制完整离线镜像目录。")
        if isinstance(exc, subprocess.CalledProcessError):
            return error("IMG004", f"Docker 操作失败：{exc}", "确认 Docker 服务、磁盘和可信离线归档；失败导入已清理。")
        return error("IMG002", str(exc), "停止安装，重新从受信发布介质取得镜像归档和清单。")
    except Exception as exc:
        if loading_started:
            try:
                remove_images(imported_tags | loaded_ids)
            except Exception:
                remove_images(imported_tags)
        return error("IMG999", str(exc), "保留脱敏现场信息并联系发布包维护人员。")


if __name__ == "__main__":
    raise SystemExit(main())
