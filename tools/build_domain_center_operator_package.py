#!/usr/bin/env python3
"""Build the public, secret-free seven-role domain-center operator package."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
from typing import Any


REPO = Path(__file__).resolve().parents[1]
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))

from build_domain_center_site_bundle import BundleError, validate_oci_archive
DEFAULT_OUTPUT = REPO / "dist" / "resolver-identity-domain-center"
VERSION = "0.3.0-norn-knot-rc15"
ROLES = (
    ("01-management", "management", "管理与全站检查"),
    ("02-norn-a", "norn-a", "Norn A 节点"),
    ("03-norn-b", "norn-b", "Norn B 节点"),
    ("04-authdns", "authdns", "权威 DNS 身份节点"),
    ("05-r3", "r3", "递归解析 R3"),
    ("06-r2", "r2", "递归解析 R2"),
    ("07-r1", "r1", "递归解析 R1 与 Wrapper"),
)
ROLE_SERVICES = {
    "management": {"management-tools": ("management", "RI_MANAGEMENT_IMAGE"), "norn-publisher": ("norn", "RI_NORN_IMAGE")},
    "norn-a": {"norn-node": ("norn", "RI_NORN_IMAGE"), "norn-read-proxy": ("nginx", "RI_NGINX_IMAGE")},
    "norn-b": {"norn-node": ("norn", "RI_NORN_IMAGE"), "norn-read-proxy": ("nginx", "RI_NGINX_IMAGE")},
    "authdns": {
        "registry-sync": ("registry-sync", "RI_REGISTRY_SYNC_IMAGE"),
        "agent": ("agent", "RI_AGENT_IMAGE"),
        "authority-proxy": ("authority-proxy", "RI_AUTHORITY_PROXY_IMAGE"),
    },
    "r3": {
        "resolver": ("resolver", "RI_KNOT_IMAGE"),
        "trace-producer": ("trace-producer", "RI_TRACE_PRODUCER_IMAGE"),
        "registry-sync": ("registry-sync", "RI_REGISTRY_SYNC_IMAGE"),
        "agent": ("agent", "RI_AGENT_IMAGE"),
        "trace-adapter": ("trace-adapter", "RI_TRACE_ADAPTER_IMAGE"),
    },
    "r2": {
        "resolver": ("resolver", "RI_KNOT_IMAGE"),
        "trace-producer": ("trace-producer", "RI_TRACE_PRODUCER_IMAGE"),
        "registry-sync": ("registry-sync", "RI_REGISTRY_SYNC_IMAGE"),
        "agent": ("agent", "RI_AGENT_IMAGE"),
        "trace-adapter": ("trace-adapter", "RI_TRACE_ADAPTER_IMAGE"),
    },
    "r1": {
        "resolver": ("resolver", "RI_KNOT_IMAGE"),
        "trace-producer": ("trace-producer", "RI_TRACE_PRODUCER_IMAGE"),
        "registry-sync": ("registry-sync", "RI_REGISTRY_SYNC_IMAGE"),
        "agent": ("agent", "RI_AGENT_IMAGE"),
        "trace-adapter": ("trace-adapter", "RI_TRACE_ADAPTER_IMAGE"),
        "wrapper": ("wrapper", "RI_WRAPPER_IMAGE"),
    },
}
ROLE_IMAGES = {
    role: tuple(dict.fromkeys(image_id for image_id, _ in services.values()))
    for role, services in ROLE_SERVICES.items()
}
IMAGE_SPECS = {
    "management": {
        "archive": "management.oci.tar",
        "repository": "offline/resolver-identity/management",
        "reference_digest": "sha256:8a6d7aeb1500996769c8bbf3396e381c7a938ca1d8b154108edf87f2d004d0a0",
        "config_digest": "sha256:015a1d4494eb01511aa723a90635862f8d66849c3fc38a9a9ae1a15e83f4586c",
        "archive_sha256": "be05dbdbf872ec5f863684cac100aadcfee616b6b4e00cb98f40ef4723f128cc",
    },
    "norn": {
        "archive": "go-norn.oci.tar",
        "repository": "offline/resolver-identity/norn",
        "reference_digest": "sha256:ad8b495d892c35b18da82d4c55899eaa8ff15d501fd63551e684a85479432323",
        "config_digest": "sha256:ebf87a3bc25d444ca7db149a0a9fdf91b238b53c38cec1ac7e6902b12091b342",
        "archive_sha256": "989893a7ee550f5fb1260e000084e182a634d8ecf5b45969c5f9fe31b6a29b06",
    },
    "nginx": {
        "archive": "mtls-read-proxy.oci.tar",
        "repository": "offline/resolver-identity/nginx",
        "reference_digest": "sha256:8d9da9cfb339e4147190984ce6a61e148e036125aaf33d09c023c3c87b0166ae",
        "config_digest": "sha256:ce7eae171b944ad0071ef0bdf932f92423dbb049c94dc66b726dd8018f69acaa",
        "archive_sha256": "b296a0d49b2d4f87054808e7ccda7cf1263f9c549b53c0199427990d8ad270c0",
    },
    "resolver": {
        "archive": "knot-trace.oci.tar",
        "repository": "offline/resolver-identity/knot",
        "reference_digest": "sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8",
        "config_digest": "sha256:04dfd24faa1d450dedf025559a75fb2e8045a9477fbd17208062553a8c826fb6",
        "archive_sha256": "dd4348db986a629c8f9bf6874e38a75baad96e1e6c0c6545d1082118a0434fa9",
    },
    "trace-producer": {
        "archive": "rust-data-plane-rc15-reconnect-strict.oci.tar",
        "repository": "offline/resolver-identity/trace-producer",
        "reference_digest": "sha256:ba61776ddb2eb0948b7c3cf4b1ffb04cac66b3a2e9da773a09c58e9449d0954c",
        "config_digest": "sha256:5a0974869334035021023ff8cf4fadba5cb1754f9cf61f73f10e4e0d5d1a592b",
        "archive_sha256": "07d5898e8879e49f9d065bfd979676e13f845c26ee8d7f4c6f117c27b96fe6bd",
    },
    "registry-sync": {
        "archive": "rust-data-plane-oci-rc14.tar",
        "repository": "offline/resolver-identity/registry-sync",
        "reference_digest": "sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80",
        "config_digest": "sha256:992362e791904eb63e3dbc2b811367f65a907f405282bab1fbb7741620bc7ec5",
        "archive_sha256": "95dc54ec9bcda0bb9f206fb24ddd23007cdba9ea490e7dda080a51584ee19f5f",
    },
    "agent": {
        "archive": "rust-data-plane-agent-stable.oci.tar",
        "repository": "offline/resolver-identity/agent",
        "reference_digest": "sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f",
        "config_digest": "sha256:82fdaaffee47a55ab3b31e6f05367a7777184e9a1a6d6e93eb1289815993d754",
        "archive_sha256": None,
    },
    "trace-adapter": {
        "archive": "rust-data-plane-trace-adapter-stable.oci.tar",
        "repository": "offline/resolver-identity/trace-adapter",
        "reference_digest": "sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f",
        "config_digest": "sha256:82fdaaffee47a55ab3b31e6f05367a7777184e9a1a6d6e93eb1289815993d754",
        "archive_sha256": None,
    },
    "wrapper": {
        "archive": "rust-data-plane-wrapper-stable.oci.tar",
        "repository": "offline/resolver-identity/wrapper",
        "reference_digest": "sha256:373ac52a774f8ffd9f92bf26d4aff2132e54287b2d21bb2d6e30d924365b13b6",
        "config_digest": "sha256:72eaeae03ee42a6b7375989f29ae285d64fb510415dfe0b6f2a77b0c57725ca5",
        "archive_sha256": None,
    },
    "authority-proxy": {
        "archive": "rust-data-plane-rc15-reconnect-strict.oci.tar",
        "repository": "offline/resolver-identity/authority-proxy",
        "reference_digest": "sha256:ba61776ddb2eb0948b7c3cf4b1ffb04cac66b3a2e9da773a09c58e9449d0954c",
        "config_digest": "sha256:5a0974869334035021023ff8cf4fadba5cb1754f9cf61f73f10e4e0d5d1a592b",
        "archive_sha256": "07d5898e8879e49f9d065bfd979676e13f845c26ee8d7f4c6f117c27b96fe6bd",
    },
}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    re.compile(rb"(?im)^[ \t]*(?:password|passphrase|secret|token|credential|api[_-]?key)[ \t]*[:=][ \t]*[^$\s{][^\r\n]{7,}$"),
)
FORBIDDEN_NAMES = re.compile(r"(?:^|/)(?:\.env|.*\.(?:db|sqlite|sqlite3|wal|shm)|id_(?:rsa|dsa|ecdsa|ed25519)|.*(?:private[_-]?key|password).*)$", re.IGNORECASE)


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def copy_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def wrapper(role: str, action: str) -> str:
    return f'''#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
exec python3 -B "$ROOT/common/domain_center_operator.py" {action} --package-root "$ROOT" --role {role} "$@"
'''


def check_all_wrapper() -> str:
    return '''#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec python3 -B "$ROOT/common/domain_center_operator.py" check-all --package-root "$ROOT" "$@"
'''


def readme() -> str:
    role_lines = "\n".join(f"- `{directory}`：{description}" for directory, _, description in ROLES)
    return f'''# 域名中心七角色离线安装包

版本：`{VERSION}`

这是面向现场管理员的公共操作包。公共包只包含操作脚本、镜像锁和可选 OCI 归档；**不包含任何私钥、令牌、密码、数据库、缓存、日志或运行状态**。每台主机还必须通过独立安全带外渠道取得专属私有配置包。

## 七个编号角色

{role_lines}

安装顺序固定为：Management → Norn A → Norn B → AuthDNS → R3 → R2 → R1。

## 管理员只需执行

进入本机对应的编号角色目录：

```bash
sudo ./install.sh
sudo ./check.sh
```

重复执行 `sudo ./install.sh` 是幂等的：镜像加载器会跳过已存在且摘要匹配的镜像，Compose 使用同一固定 project 执行 `up -d --remove-orphans`。安装过程不会执行 `docker pull`，也不会删除 volume 或业务数据。

故障时：

```bash
sudo ./diagnose.sh
```

诊断文件写入 `/var/log/resolver-identity-domain-center/`，权限为 0600；输出会脱敏 Authorization、Cookie、密码、令牌、JWT、凭据 URL 和私钥块。诊断脚本不收集业务数据库、Resolver cache 或私有包内容。

Management 主机可在配置独立的 0600 `site-inventory.json` 和 SSH `known_hosts` 后执行：

```bash
sudo ./check-all.sh --inventory /etc/resolver-identity/domain-center/site-inventory.json
```

全站检查使用 `BatchMode=yes`、`StrictHostKeyChecking=yes` 和指定 `known_hosts`，逐台只运行远端 `sudo -n <角色目录>/check.sh`。

## 私有配置包要求

默认目录：`/etc/resolver-identity/domain-center/<role>/`。目录及子目录必须属于 root，目录 0700、文件 0600，禁止符号链接。根目录必须有 `bundle.json`，格式示例：

```json
{{
  "schema_version": "resolver-identity-domain-center-private-bundle-v1",
  "role": "r1",
  "expected_host": "ri-r1",
  "compose_project": "ri-r1",
  "compose": {{"path": "compose.yml", "sha256": "<64位小写SHA-256>"}},
  "environment": {{"path": "node.env", "sha256": "<64位小写SHA-256>"}},
  "secrets": "secrets"
}}
```

`compose.yml` 与 `node.env` 来自私有交接，不属于公共包；脚本会校验角色、主机名、所有权、权限和 SHA-256。`secrets/` 全树只允许 0700 目录和 0600 普通文件。禁止把私有包复制进本公共目录或提交到 Git。

## OCI 缺失状态

构建器只复制真实且摘要正确的 OCI。若某归档缺失或未提供足够的 config digest，构建仍可生成结构包，但会在 `MANIFEST.json` 的 `missing_oci_archives` 中明确记录，角色安装将以 `IMG001` 失败；不会制造空归档或回退到在线拉取。

## 完整性

分发前和每次安装/检查都会验证根目录 `SHA256SUMS`。`MANIFEST.json` 记录版本、七角色、公共文件和 OCI 缺失状态。不得在验签后修改包内文件。
'''


def role_readme(role: str, description: str) -> str:
    return f'''# {description}

本目录固定角色为 `{role}`，不能通过命令行改成其他角色。

1. 通过安全带外流程将该主机私有包安装到 `/etc/resolver-identity/domain-center/{role}/`，并确保 root:root、目录 0700、文件 0600。
2. 执行 `sudo ./install.sh`。
3. 执行 `sudo ./check.sh`。
4. 若失败执行 `sudo ./diagnose.sh`，只发送生成的脱敏日志，不发送私有配置、证书、密钥、数据库或缓存。

脚本离线运行，不执行镜像 pull；重复安装会续跑并收敛到相同 Compose 状态。
'''


def image_entry(key: str, source: Path) -> dict[str, str]:
    spec = IMAGE_SPECS[key]
    digest = spec.get("reference_digest")
    config_digest = spec.get("config_digest")
    if not isinstance(digest, str) or not isinstance(config_digest, str):
        raise BuildError(f"{key}: missing trusted OCI manifest/config digest")
    expected_archive = spec.get("archive_sha256")
    actual_archive = sha256(source)
    if isinstance(expected_archive, str) and actual_archive != expected_archive:
        raise BuildError(f"{key}: OCI archive SHA-256 mismatch")
    try:
        validated = validate_oci_archive(
            source,
            digest,
            {"os": "linux", "architecture": "amd64"},
        )
    except BundleError as exc:
        raise BuildError(f"{key}: OCI validation failed: {exc}") from exc
    if validated["config_digest"] != config_digest:
        raise BuildError(f"{key}: OCI config digest mismatch")
    repository = str(spec["repository"])
    return {
        "id": key,
        "archive_id": key,
        "reference": f"{repository}@{digest}",
        "import_reference": f"{repository}:ri-{digest.split(':', 1)[1][:16]}",
        "digest": digest,
        "config_digest": config_digest,
        "archive": str(spec["archive"]),
        "archive_sha256": actual_archive,
    }


def add_images(output: Path, image_sources: dict[str, Path]) -> list[str]:
    missing: set[str] = set()
    cache: dict[str, dict[str, str]] = {}
    for key, spec in IMAGE_SPECS.items():
        source = image_sources.get(key)
        if source is None:
            missing.add(key)
            continue
        if not source.is_file() or source.is_symlink():
            missing.add(key)
            continue
        try:
            cache[key] = image_entry(key, source)
        except BuildError:
            missing.add(key)
    for directory, role, _ in ROLES:
        role_path = output / directory
        entries: list[dict[str, str]] = []
        role_missing = [key for key in ROLE_IMAGES[role] if key not in cache]
        if role_missing:
            missing.update(role_missing)
            continue
        images = role_path / "images"
        images.mkdir(parents=True, exist_ok=True)
        archives: list[dict[str, str]] = []
        copied_archives: set[str] = set()
        for key in ROLE_IMAGES[role]:
            entry = cache[key]
            source = image_sources[key]
            archive = entry["archive"]
            if archive not in copied_archives:
                copy_file(source, images / archive, 0o644)
                copied_archives.add(archive)
            archives.append({
                "id": entry["archive_id"],
                "archive": archive,
                "archive_sha256": entry["archive_sha256"],
            })
            entries.append({key: value for key, value in entry.items() if key not in {"archive", "archive_sha256"}})
        services = [
            {"service": service, "compose_variable": variable, "image_id": image_id}
            for service, (image_id, variable) in ROLE_SERVICES[role].items()
        ]
        write_json(images / "image-lock.json", {
            "schema_version": "resolver-identity-role-image-lock-v2",
            "hostname": f"private-bundle:{role}",
            "role": role,
            "archives": archives,
            "images": entries,
            "services": services,
        })
    return sorted(missing)


def public_files(root: Path) -> list[dict[str, object]]:
    result = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {"SHA256SUMS", "MANIFEST.json"}:
            continue
        result.append({"path": path.relative_to(root).as_posix(), "sha256": sha256(path), "size": path.stat().st_size})
    return result


def write_sums(root: Path) -> None:
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path != root / "SHA256SUMS":
            records.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}")
    write_text(root / "SHA256SUMS", "\n".join(records) + "\n")


def write_archive(root: Path) -> Path:
    archive = root.parent / f"{root.name}-{VERSION}.tar"
    temporary = archive.parent / f".{archive.name}.tmp-{os.getpid()}"
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1786233600"))
    with temporary.open("wb") as output, tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in [root, *sorted(root.rglob("*"))]:
            relative = Path(root.name) / path.relative_to(root)
            info = tar.gettarinfo(str(path), arcname=relative.as_posix())
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.pax_headers = {}
            if path.is_file():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
    os.replace(temporary, archive)
    write_text(Path(f"{archive}.sha256"), f"{sha256(archive)}  {archive.name}\n")
    return archive


def scan_public(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BuildError(f"public package contains symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if FORBIDDEN_NAMES.search(relative):
            raise BuildError(f"public package contains forbidden secret/runtime filename: {relative}")
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            raise BuildError(f"public package contains generated Python bytecode: {relative}")
        if path.suffix == ".tar":
            continue
        if path.stat().st_size <= 16 * 1024 * 1024:
            data = path.read_bytes()
            if any(pattern.search(data) for pattern in SECRET_PATTERNS):
                raise BuildError(f"public package contains secret-like material: {relative}")


def build(output: Path, image_sources: dict[str, Path] | None = None) -> dict[str, object]:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.tmp-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        write_text(staging / "VERSION", VERSION + "\n")
        write_text(staging / "README.md", readme())
        write_text(staging / "check-all.sh", check_all_wrapper(), 0o755)
        common = staging / "common"
        copy_file(REPO / "tools" / "domain_center_operator.py", common / "domain_center_operator.py", 0o755)
        copy_file(REPO / "deploy" / "easy-install" / "product-kit" / "common" / "load_images.py", common / "load_images.py", 0o755)
        for directory, role, description in ROLES:
            target = staging / directory
            target.mkdir()
            write_text(target / "README.md", role_readme(role, description))
            for name, action in (("install.sh", "install"), ("check.sh", "check"), ("diagnose.sh", "diagnose")):
                write_text(target / name, wrapper(role, action), 0o755)
        missing = add_images(staging, image_sources or {})
        generated_at = dt.datetime.fromtimestamp(
            int(os.environ.get("SOURCE_DATE_EPOCH", "1786233600")), dt.UTC
        ).replace(microsecond=0).isoformat()
        manifest = {
            "schema_version": "resolver-identity-domain-center-public-operator-package-v1",
            "version": VERSION,
            "generated_at": generated_at,
            "roles": [{"directory": directory, "role": role, "description_zh": description} for directory, role, description in ROLES],
            "install_order": [role for _, role, _ in ROLES],
            "public_payload": True,
            "contains_secrets": False,
            "contains_database": False,
            "contains_runtime_state": False,
            "offline_only": True,
            "missing_oci_archives": missing,
            "files": public_files(staging),
        }
        write_json(staging / "MANIFEST.json", manifest)
        write_sums(staging)
        scan_public(staging)
        if output.exists():
            shutil.rmtree(output)
        os.replace(staging, output)
        write_archive(output)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_sources(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise BuildError("--image-source must be KEY=/absolute/archive.tar")
        key, raw = value.split("=", 1)
        if key not in IMAGE_SPECS or key in result or not Path(raw).is_absolute():
            raise BuildError(f"invalid --image-source: {value}")
        result[key] = Path(raw)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--image-source", action="append", default=[], metavar="KEY=/ABSOLUTE/ARCHIVE")
    args = parser.parse_args()
    try:
        manifest = build(args.output, parse_sources(args.image_source))
        print(json.dumps({"output": str(args.output.resolve()), "version": VERSION, "missing_oci_archives": manifest["missing_oci_archives"]}, ensure_ascii=False, sort_keys=True))
        return 0 if not manifest["missing_oci_archives"] else 3
    except (BuildError, OSError, ValueError) as exc:
        print(f"domain-center operator package error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
