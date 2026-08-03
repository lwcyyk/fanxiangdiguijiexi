#!/usr/bin/env python3
"""严格校验并加载离线 OCI 镜像；使用本地确定性标签，不执行 registry pull。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


LOCK_SCHEMA = "resolver-identity-role-image-lock-v1"
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


def parse_manifest(path: Path) -> list[tuple[Path, str, str, str, str]]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageError(f"无法读取镜像清单：{exc}") from exc
    if not isinstance(obj, dict) or obj.get("schema_version") != LOCK_SCHEMA:
        raise ImageError("镜像清单 schema_version 不受支持")
    if set(obj) != {"schema_version", "hostname", "role", "images"}:
        raise ImageError("镜像清单字段集合不合法")
    entries = obj.get("images")
    if not isinstance(entries, list) or not entries:
        raise ImageError("镜像清单 images 必须是非空数组")
    parsed: list[tuple[Path, str, str, str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key", "reference", "import_reference", "digest", "config_digest", "archive", "archive_sha256"
        }:
            raise ImageError("镜像清单条目字段集合不合法")
        filename = entry["archive"]
        checksum = entry["archive_sha256"]
        reference = entry["reference"]
        import_reference = entry["import_reference"]
        digest = entry["digest"]
        config_digest = entry["config_digest"]
        if not isinstance(filename, str) or Path(filename).name != filename or filename in seen:
            raise ImageError("归档文件名必须是唯一的单一安全文件名")
        seen.add(filename)
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ImageError(f"归档校验值不合法：{filename}")
        match = REFERENCE_RE.fullmatch(reference) if isinstance(reference, str) else None
        if match is None or match.group(2) != digest or (":late" + "st") in reference.lower() or "localhost" in reference.lower():
            raise ImageError(f"原始 OCI 摘要引用不合法：{filename}")
        expected_import = f"{match.group(1)}:ri-{digest.split(':', 1)[1][:16]}"
        if not isinstance(import_reference, str) or IMPORT_RE.fullmatch(import_reference) is None or import_reference != expected_import:
            raise ImageError(f"OCI 本地导入标签不合法：{filename}")
        if not isinstance(config_digest, str) or DIGEST_RE.fullmatch(config_digest) is None:
            raise ImageError(f"OCI config digest 不合法：{filename}")
        parsed.append((path.parent / filename, checksum, reference, import_reference, config_digest))
    return parsed


def verify_loaded(import_reference: str, config_digest: str) -> None:
    image = inspect_image(import_reference)
    image_id = image.get("Id")
    tags = image.get("RepoTags")
    if image_id != config_digest:
        raise ImageError(f"加载后镜像 ID 与已校验 OCI config digest 不一致：{import_reference}")
    if not isinstance(tags, list) or import_reference not in tags:
        raise ImageError(f"加载后未找到确定性本地标签：{import_reference}")


def main() -> int:
    parser = argparse.ArgumentParser(description="严格校验并加载离线 OCI 镜像")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    imported_tags: set[str] = set()
    before_ids: set[str] = set()
    loading_started = False
    try:
        entries = parse_manifest(args.directory.resolve() / "image-lock.json")
        for archive, expected, _, _, _ in entries:
            if not archive.is_file() or archive.is_symlink() or sha256(archive) != expected:
                raise ImageError(f"归档校验失败：{archive.name}")
            print(f"归档校验通过：{archive.name}")
        if args.verify_only:
            return 0
        subprocess.run(["docker", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        before_ids = image_ids()
        loading_started = True
        for archive, _, original_reference, import_reference, config_digest in entries:
            preexisting = False
            try:
                verify_loaded(import_reference, config_digest)
                preexisting = True
            except (ImageError, subprocess.CalledProcessError):
                pass
            if not preexisting:
                subprocess.run(["docker", "load", "--input", str(archive)], check=True)
                subprocess.run(["docker", "image", "tag", config_digest, import_reference], check=True)
                imported_tags.add(import_reference)
            verify_loaded(import_reference, config_digest)
            print(f"加载校验通过：本地标签 {import_reference}；原始 OCI manifest {original_reference}")
        return 0
    except (ImageError, OSError, subprocess.CalledProcessError) as exc:
        if loading_started:
            try:
                remove_images(imported_tags | (image_ids() - before_ids))
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
                remove_images(imported_tags | (image_ids() - before_ids))
            except Exception:
                remove_images(imported_tags)
        return error("IMG999", str(exc), "保留脱敏现场信息并联系发布包维护人员。")


if __name__ == "__main__":
    raise SystemExit(main())
