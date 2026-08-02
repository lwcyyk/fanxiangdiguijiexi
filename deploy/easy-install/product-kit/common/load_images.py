#!/usr/bin/env python3
"""离线镜像校验、加载及加载后 RepoDigest 校验；不依赖 jq。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


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


def digest_from_reference(reference: str) -> str:
    match = re.fullmatch(r"[^\s@]+@sha256:([0-9a-f]{64})", reference)
    if not match or (":late" + "st@") in reference:
        raise ImageError(f"镜像未使用完整 sha256 固定：{reference}")
    return match.group(1)


def inspect_digests(reference: str) -> set[str]:
    result = subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{json .RepoDigests}}"],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        values = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise ImageError(f"docker inspect 返回不可解析：{exc}") from exc
    if not isinstance(values, list):
        raise ImageError("docker inspect 未返回 RepoDigests 列表")
    return {str(value) for value in values if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", str(value))}


def parse_manifest(path: Path) -> list[tuple[Path, str, str]]:
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
        filename = entry.get("archive")
        checksum = entry.get("archive_sha256")
        reference = entry.get("reference")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ImageError("归档文件名必须是单一安全文件名")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ImageError(f"归档校验值不合法：{filename}")
        if not isinstance(reference, str):
            raise ImageError(f"镜像引用缺失：{filename}")
        digest_from_reference(reference)
        parsed.append((path.parent / filename, checksum, reference))
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="校验并加载离线 OCI/Docker 镜像归档")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        manifest = args.directory.resolve() / "image-lock.json"
        entries = parse_manifest(manifest)
        for archive, expected_archive, reference in entries:
            if not archive.is_file() or archive.is_symlink():
                raise ImageError(f"归档不存在或为符号链接：{archive.name}")
            actual = sha256(archive)
            if actual != expected_archive:
                raise ImageError(f"归档校验失败：{archive.name}，期望 {expected_archive}，实际 {actual}")
            print(f"归档校验通过：{archive.name}")
        if args.verify_only:
            return 0
        subprocess.run(["docker", "version"], check=True, stdout=subprocess.DEVNULL)
        for archive, _, reference in entries:
            subprocess.run(["docker", "load", "--input", str(archive)], check=True)
            actual = inspect_digests(reference)
            if reference not in actual:
                raise ImageError(f"加载后镜像摘要不匹配：{reference}；RepoDigests={sorted(actual)}")
            print(f"加载后摘要校验通过：{reference}")
        return 0
    except FileNotFoundError as exc:
        return error("IMG003", f"所需命令或文件不存在：{exc}", "安装 Docker 并重新复制完整离线镜像目录。")
    except subprocess.CalledProcessError as exc:
        return error("IMG004", f"Docker 操作失败：{exc}", "确认 Docker 服务可用、磁盘充足，然后重新执行；已加载镜像可复用。")
    except ImageError as exc:
        return error("IMG002", str(exc), "停止安装，重新从受信发布介质取得镜像归档和清单。")
    except Exception as exc:
        return error("IMG999", str(exc), "保留现场并联系发布包维护人员。")


if __name__ == "__main__":
    sys.exit(main())
