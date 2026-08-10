#!/usr/bin/env python3
"""Simple, fail-closed operator for the seven-role domain-center offline package."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROLES = (
    "management",
    "norn-a",
    "norn-b",
    "authdns",
    "r3",
    "r2",
    "r1",
)
ROLE_DIRECTORIES = {
    "management": "01-management",
    "norn-a": "02-norn-a",
    "norn-b": "03-norn-b",
    "authdns": "04-authdns",
    "r3": "05-r3",
    "r2": "06-r2",
    "r1": "07-r1",
}
BUNDLE_SCHEMA = "resolver-identity-domain-center-private-bundle-v1"
INVENTORY_SCHEMA = "resolver-identity-domain-center-check-inventory-v1"
PEM_PRIVATE_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.DOTALL)
AUTH_RE = re.compile(r"(?im)^([ \t]*(?:authorization|proxy-authorization)[ \t]*:[ \t]*).+$")
COOKIE_RE = re.compile(r"(?im)^([ \t]*(?:cookie|set-cookie)[ \t]*:[ \t]*).+$")
ASSIGNMENT_RE = re.compile(r"(?im)^([ \t]*(?:[A-Za-z][A-Za-z0-9_.-]*)?(?:password|passphrase|secret|token|credential|api[_-]?key)[A-Za-z0-9_.-]*[ \t]*[:=][ \t]*).+$")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
URL_RE = re.compile(r"https?://[^\s<>\"]+")
SENSITIVE_QUERY_RE = re.compile(r"(?:password|passphrase|secret|token|credential|api[_-]?key)", re.IGNORECASE)
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
SAFE_TARGET_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
SAFE_REMOTE_ROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")


class OperatorError(RuntimeError):
    def __init__(self, code: str, reason: str, advice: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.advice = advice


def fail(code: str, reason: str, advice: str) -> None:
    raise OperatorError(code, reason, advice)


def redact_url(match: re.Match[str]) -> str:
    try:
        parsed = urlsplit(match.group(0))
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        query = urlencode([
            (key, "[REDACTED]" if SENSITIVE_QUERY_RE.search(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path, query, ""))
    except ValueError:
        return "[REDACTED URL]"


def redact(value: str) -> str:
    value = PEM_PRIVATE_RE.sub("[REDACTED PRIVATE KEY]", value)
    value = AUTH_RE.sub(r"\1[REDACTED]", value)
    value = COOKIE_RE.sub(r"\1[REDACTED]", value)
    value = ASSIGNMENT_RE.sub(r"\1[REDACTED]", value)
    value = JWT_RE.sub("[REDACTED JWT]", value)
    return URL_RE.sub(redact_url, value)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail("BUNDLE002", f"无法读取{label}：{path}：{exc}", "重新复制完整的私有配置包；不要手工修补内容。")
    if not isinstance(value, dict):
        fail("BUNDLE002", f"{label}必须是 JSON 对象：{path}", "使用发布方提供的私有配置包。")
    return value


def require_root() -> None:
    if os.geteuid() != 0:
        fail("PERM001", "该命令必须以 root 运行", "在角色目录执行 sudo ./install.sh、sudo ./check.sh 或 sudo ./diagnose.sh。")


def package_root(path: Path) -> Path:
    root = path.resolve()
    if not (root / "VERSION").is_file() or not (root / "MANIFEST.json").is_file() or not (root / "SHA256SUMS").is_file():
        fail("PKG001", f"公共包元数据不完整：{root}", "重新复制完整公共离线包。")
    return root


def verify_package(root: Path) -> None:
    records: dict[str, str] = {}
    try:
        lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail("PKG002", f"公共包 SHA256 清单不可读：{exc}", "停止安装，从可信发布介质重新复制公共包。")
    for number, line in enumerate(lines, 1):
        match = SUM_LINE_RE.fullmatch(line)
        if match is None:
            fail("PKG002", f"公共包 SHA256 清单第 {number} 行不合法", "停止安装，从可信发布介质重新复制公共包。")
        relative = match.group(2)
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or relative in records or relative == "SHA256SUMS":
            fail("PKG002", f"公共包 SHA256 路径不合法或重复：{relative}", "停止安装，从可信发布介质重新复制公共包。")
        records[relative] = match.group(1)
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail("PKG002", f"公共包包含符号链接：{path.relative_to(root)}", "停止安装，从可信发布介质重新复制公共包。")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative == "SHA256SUMS":
                continue
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                fail("PKG002", f"公共包包含生成字节码：{relative}", "停止安装，从可信发布介质重新复制公共包。")
            actual.add(relative)
    if actual != set(records):
        extra = sorted(actual - set(records))
        missing = sorted(set(records) - actual)
        fail("PKG002", f"公共包文件集合与清单不一致：extra={extra} missing={missing}", "停止安装，从可信发布介质重新复制公共包。")
    for relative, expected in records.items():
        path = root / relative
        if not path.is_file() or sha256(path) != expected:
            fail("PKG002", f"公共包 SHA256 校验失败：{relative}", "停止安装，从可信发布介质重新复制公共包。")


def check_owner_mode(path: Path, expected_mode: int, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        fail("BUNDLE003", f"{label}不存在或不可读：{path}：{exc}", "修复私有包后重试。")
    if stat.S_ISLNK(info.st_mode):
        fail("BUNDLE004", f"{label}不能是符号链接：{path}", "使用 root 拥有的真实文件或目录。")
    if info.st_uid != 0 or info.st_gid != 0:
        fail("BUNDLE005", f"{label}必须由 root:root 拥有：{path}", "执行 chown root:root 并重新检查私有包来源。")
    actual = stat.S_IMODE(info.st_mode)
    if actual != expected_mode:
        fail("BUNDLE006", f"{label}权限必须是 {expected_mode:04o}，实际为 {actual:04o}：{path}", "收紧权限后重试；不要放宽私钥或配置权限。")


def safe_relative(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
        fail("BUNDLE007", f"{label}必须是私有包内安全相对路径", "使用发布方生成的 bundle.json。")
    candidate = root / value
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        fail("BUNDLE007", f"{label}越出私有包目录", "使用发布方生成的 bundle.json。")
    return candidate


def validate_file_record(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        fail("BUNDLE008", f"bundle.json 的 {label}记录字段不合法", "重新取得完整私有包。")
    path = safe_relative(root, record.get("path"), label)
    check_owner_mode(path, 0o600, label)
    if not path.is_file():
        fail("BUNDLE003", f"{label}不是普通文件：{path}", "重新取得完整私有包。")
    expected = record.get("sha256")
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None or sha256(path) != expected:
        fail("BUNDLE009", f"{label}摘要不匹配：{path.name}", "停止安装，重新取得可信私有包。")
    return path


def host_names() -> set[str]:
    values = {socket.gethostname(), socket.getfqdn()}
    values.update(value.split(".", 1)[0] for value in tuple(values))
    return {value.lower().rstrip(".") for value in values if value}


def validate_secret_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        fail("BUNDLE010", f"密钥目录不是安全目录：{root}", "重新取得完整私有包。")
    for path in [root, *sorted(root.rglob("*"))]:
        try:
            info = path.lstat()
        except OSError as exc:
            fail("BUNDLE003", f"密钥对象不可读：{path}：{exc}", "重新取得完整私有包。")
        if path.is_symlink():
            fail("BUNDLE004", f"密钥树禁止符号链接：{path}", "移除链接并通过安全带外流程重建私有包。")
        if info.st_uid != 0 or info.st_gid not in {0, 10002}:
            fail("BUNDLE005", f"密钥对象所有权不合法：{path}", "使用 root:root 或 root:10002 的只读运行时交付。")
        actual = stat.S_IMODE(info.st_mode)
        if path.is_dir() and actual not in {0o700, 0o750}:
            fail("BUNDLE006", f"密钥目录权限必须是 0700 或 0750：{path}", "运行时挂载目录可用 root:10002 0750。")
        if path.is_file() and actual not in {0o600, 0o640}:
            fail("BUNDLE006", f"密钥文件权限必须是 0600 或 0640：{path}", "运行时挂载文件可用 root:10002 0640。")
        if not path.is_dir() and not path.is_file():
            fail("BUNDLE010", f"密钥树包含非常规对象：{path}", "只允许普通文件和目录。")


def validate_private_bundle(role: str, path: Path | None) -> dict[str, object]:
    root = (path or Path(f"/etc/resolver-identity/domain-center/{role}")).absolute()
    check_owner_mode(root, 0o700, "私有包目录")
    if not root.is_dir():
        fail("BUNDLE003", f"私有包目录不存在：{root}", "通过安全带外流程部署该角色私有包。")
    manifest_path = root / "bundle.json"
    check_owner_mode(manifest_path, 0o600, "私有包清单")
    manifest = load_object(manifest_path, "私有包清单")
    required = {"schema_version", "role", "expected_host", "compose_project", "compose", "environment", "secrets"}
    if set(manifest) != required or manifest.get("schema_version") != BUNDLE_SCHEMA or manifest.get("role") != role:
        fail("BUNDLE011", "私有包 schema、字段或角色不匹配", "禁止跨角色复用；重新取得该主机专属私有包。")
    expected_host = manifest.get("expected_host")
    if not isinstance(expected_host, str) or SAFE_HOST_RE.fullmatch(expected_host) is None:
        fail("BUNDLE012", "私有包 expected_host 不合法", "重新生成主机专属私有包。")
    if expected_host.lower().rstrip(".") not in host_names():
        fail("HOST001", f"私有包绑定主机 {expected_host}，当前主机不匹配", "在正确主机执行，禁止通过参数绕过主机绑定。")
    project = manifest.get("compose_project")
    if not isinstance(project, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project) is None:
        fail("BUNDLE012", "私有包 compose_project 不合法", "使用与该主机当前/目标 Compose project 一致的安全名称。")
    compose = validate_file_record(root, manifest.get("compose"), "Compose 文件")
    environment = validate_file_record(root, manifest.get("environment"), "环境配置")
    secrets = safe_relative(root, manifest.get("secrets"), "secrets")
    validate_secret_tree(secrets)
    return {
        "root": root,
        "host": expected_host,
        "project": project,
        "compose": compose,
        "environment": environment,
        "secrets": secrets,
    }


def role_root(root: Path, role: str) -> Path:
    path = root / ROLE_DIRECTORIES[role]
    if not path.is_dir():
        fail("PKG003", f"公共包缺少角色目录：{ROLE_DIRECTORIES[role]}", "重新复制完整公共包。")
    return path


def run(command: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        combined = redact((result.stdout or "") + (result.stderr or ""))[-4000:]
        fail("CMD001", f"命令失败（{shlex.join(command[:4])}）：{combined}", "保留脱敏诊断日志，修复 Docker、Compose 或私有配置后用同一命令续跑。")
    return result


def compose_command(bundle: dict[str, object], role: str, *arguments: str) -> list[str]:
    project = str(bundle["project"])
    return [
        "docker", "compose", "--project-name", project,
        "--env-file", str(bundle["environment"]),
        "-f", str(bundle["compose"]),
        *arguments,
    ]


def expected_service_images(root: Path, role: str) -> dict[str, str]:
    lock = load_object(role_root(root, role) / "images" / "image-lock.json", "镜像锁")
    entries = lock.get("images")
    bindings = lock.get("services")
    if lock.get("schema_version") != "resolver-identity-role-image-lock-v2":
        fail("IMG001", "镜像锁不是服务级 v2 格式", "重新取得包含 service → image → archive 映射的公共包。")
    if not isinstance(entries, list) or not entries or not isinstance(bindings, list) or not bindings:
        fail("IMG001", "镜像锁缺少镜像或服务绑定", "重新取得完整公共包。")
    images: dict[str, str] = {}
    for entry in entries:
        image_id = entry.get("id") if isinstance(entry, dict) else None
        reference = entry.get("import_reference") if isinstance(entry, dict) else None
        if not isinstance(image_id, str) or not isinstance(reference, str) or not reference or image_id in images:
            fail("IMG001", "镜像锁 image id/import_reference 不合法", "重新取得完整公共包。")
        images[image_id] = reference
    result: dict[str, str] = {}
    for binding in bindings:
        service = binding.get("service") if isinstance(binding, dict) else None
        image_id = binding.get("image_id") if isinstance(binding, dict) else None
        if not isinstance(service, str) or not isinstance(image_id, str) or image_id not in images or service in result:
            fail("IMG001", "镜像锁服务绑定不合法", "重新取得完整公共包。")
        result[service] = images[image_id]
    return result


def verify_compose_images(root: Path, bundle: dict[str, object], role: str) -> None:
    rendered = run(compose_command(bundle, role, "config", "--format", "json")).stdout
    try:
        document = json.loads(rendered)
        services = document["services"]
        actual = {name: value["image"] for name, value in services.items()}
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        fail("IMG005", f"无法解析 Compose 服务镜像：{exc}", "确认 Docker Compose 支持 config --format json。")
    expected = expected_service_images(root, role)
    if actual != expected:
        fail("IMG005", f"Compose 服务镜像与离线锁不一致：actual={actual} expected={expected}", "修复私有 node.env；每个服务必须精确使用 image-lock.json 指定的本地导入标签。")


def load_images(root: Path, role: str) -> None:
    images = role_root(root, role) / "images"
    lock = images / "image-lock.json"
    if not lock.is_file():
        manifest = load_object(root / "MANIFEST.json", "公共包清单")
        missing = manifest.get("missing_oci_archives", [])
        detail = "、".join(str(item) for item in missing) if isinstance(missing, list) and missing else "该角色离线 OCI 归档"
        fail("IMG001", f"公共包未包含可加载的镜像锁文件：{detail}", "由发布工程重新构建含真实 OCI 归档的公共包；禁止在线 pull 或伪造归档。")
    loader = root / "common" / "load_images.py"
    result = run([sys.executable, str(loader), str(images)], check=False)
    if result.returncode != 0:
        fail("IMG002", redact((result.stdout or "") + (result.stderr or ""))[-4000:], "检查离线归档完整性、Docker 服务与磁盘空间；禁止改用 docker pull。")


def write_state(role: str, host: str, version: str) -> None:
    state_root = Path("/var/lib/resolver-identity-domain-center/operator")
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_root, 0o700)
    value = {
        "schema_version": "resolver-identity-domain-center-operator-state-v1",
        "role": role,
        "host": host,
        "version": version,
        "installed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
    }
    destination = state_root / f"{role}.json"
    fd, temporary = tempfile.mkstemp(prefix=f".{role}.", dir=state_root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(args: argparse.Namespace) -> None:
    root = package_root(args.package_root)
    verify_package(root)
    bundle = validate_private_bundle(args.role, args.private_bundle)
    run(["docker", "version"])
    run(["docker", "compose", "version"])
    load_images(root, args.role)
    run(compose_command(bundle, args.role, "config", "--quiet"))
    verify_compose_images(root, bundle, args.role)
    if args.role == "management":
        run(compose_command(bundle, args.role, "--profile", "tools", "up", "-d", "--pull", "never", "--remove-orphans", "management-tools"))
    else:
        run(compose_command(bundle, args.role, "up", "-d", "--pull", "never", "--remove-orphans"))
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    write_state(args.role, str(bundle["host"]), version)
    check(args, verify=False)
    print(f"安装完成：role={args.role} host={bundle['host']} version={version}")


def check(args: argparse.Namespace, *, verify: bool = True) -> None:
    root = package_root(args.package_root)
    if verify:
        verify_package(root)
    bundle = validate_private_bundle(args.role, args.private_bundle)
    run(["docker", "version"])
    run(compose_command(bundle, args.role, "config", "--quiet"))
    verify_compose_images(root, bundle, args.role)
    config_tail = ("--profile", "tools", "config", "--services") if args.role == "management" else ("config", "--services")
    configured = run(compose_command(bundle, args.role, *config_tail)).stdout.splitlines()
    running = run(compose_command(bundle, args.role, "ps", "--services", "--filter", "status=running")).stdout.splitlines()
    configured_set = {item.strip() for item in configured if item.strip()}
    running_set = {item.strip() for item in running if item.strip()}
    if not configured_set:
        fail("CHECK002", "Compose 未配置任何应运行服务", "检查角色 Compose 与 profile 配置。")
    missing = sorted(configured_set - running_set)
    if missing:
        fail("CHECK001", f"以下服务未运行：{', '.join(missing)}", "执行 sudo ./diagnose.sh 收集脱敏日志，修复后重新执行 sudo ./install.sh。")
    result = run(compose_command(bundle, args.role, "ps"), check=False)
    if result.stdout:
        print(redact(result.stdout), end="")
    print(f"检查通过：role={args.role} host={bundle['host']} services={len(configured_set)}")


def diagnose(args: argparse.Namespace) -> None:
    root = package_root(args.package_root)
    verify_package(root)
    output = args.output or Path("/var/log/resolver-identity-domain-center")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = output / f"diagnose-{args.role}-{stamp}.log"
    lines = [
        f"generated_at={stamp}",
        f"role={args.role}",
        f"hostname={socket.gethostname()}",
        f"platform={platform.platform()}",
        f"package_version={(root / 'VERSION').read_text(encoding='utf-8').strip()}",
    ]
    for command in (["docker", "version"], ["docker", "compose", "version"], ["df", "-h", "/var/lib/docker"]):
        result = run(list(command), check=False)
        lines.append(f"\n$ {shlex.join(command)}\n{result.stdout}{result.stderr}")
    try:
        bundle = validate_private_bundle(args.role, args.private_bundle)
        for tail in (("config", "--services"), ("ps",), ("ps", "--all")):
            command = compose_command(bundle, args.role, *tail)
            result = run(command, check=False)
            lines.append(f"\n$ docker compose {' '.join(tail)}\n{result.stdout}{result.stderr}")
    except OperatorError as exc:
        lines.append(f"\nprivate_bundle_status={exc.code}: {exc.reason}\n")
    text = redact("\n".join(lines))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")
    print(f"脱敏诊断日志已生成：{destination}")


def validate_inventory(path: Path) -> tuple[Path, list[dict[str, str]]]:
    check_owner_mode(path, 0o600, "全站检查清单")
    value = load_object(path, "全站检查清单")
    if set(value) != {"schema_version", "known_hosts", "hosts"} or value.get("schema_version") != INVENTORY_SCHEMA:
        fail("SITE001", "全站检查清单 schema 或字段不合法", "使用发布方生成的 site-inventory.json。")
    known_hosts = Path(str(value.get("known_hosts", "")))
    if not known_hosts.is_absolute():
        fail("SITE001", "SSH known_hosts 必须是绝对路径", "使用 root:root、0600 的固定绝对路径。")
    check_owner_mode(known_hosts, 0o600, "SSH known_hosts")
    raw_hosts = value.get("hosts")
    if not isinstance(raw_hosts, list) or len(raw_hosts) != len(ROLES):
        fail("SITE002", "全站检查清单必须恰好包含七个角色", "补齐七角色并重新生成清单。")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_hosts:
        if not isinstance(raw, dict) or set(raw) != {"role", "target", "package_root"}:
            fail("SITE003", "全站主机记录字段不合法", "使用 role、target、package_root 三个字段。")
        role, target, install_root = raw.get("role"), raw.get("target"), raw.get("package_root")
        if role not in ROLES or role in seen or not isinstance(target, str) or SAFE_TARGET_RE.fullmatch(target) is None:
            fail("SITE003", "全站主机角色或 SSH target 不合法/重复", "每个固定角色只配置一次可信 SSH 目标。")
        if not isinstance(install_root, str) or SAFE_REMOTE_ROOT_RE.fullmatch(install_root) is None or ".." in Path(install_root).parts:
            fail("SITE003", "远端 package_root 必须是安全绝对路径", "配置只含字母、数字、点、下划线、连字符和斜杠的固定路径。")
        seen.add(str(role))
        records.append({"role": str(role), "target": target, "package_root": install_root})
    if seen != set(ROLES):
        fail("SITE002", "全站检查清单角色集合不完整", "补齐七角色。")
    return known_hosts, records


def check_all(args: argparse.Namespace) -> None:
    root = package_root(args.package_root)
    verify_package(root)
    inventory = args.inventory or Path("/etc/resolver-identity/domain-center/site-inventory.json")
    known_hosts, records = validate_inventory(inventory)
    failures: list[str] = []
    for record in records:
        role = record["role"]
        remote_script = f"{record['package_root'].rstrip('/')}/{ROLE_DIRECTORIES[role]}/check.sh"
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}", record["target"],
            "sudo", "-n", remote_script,
        ]
        result = run(command, check=False)
        output = redact((result.stdout or "") + (result.stderr or ""))
        print(f"[{role}] {record['target']}\n{output}", end="" if output.endswith("\n") else "\n")
        if result.returncode != 0:
            failures.append(role)
    if failures:
        fail("SITE004", f"全站检查失败角色：{', '.join(failures)}", "分别执行对应角色 diagnose.sh，保留脱敏日志后修复。")
    print("七角色全站检查通过。")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="域名中心七角色离线包操作层")
    value.add_argument("action", choices=("install", "check", "diagnose", "check-all"))
    value.add_argument("--package-root", required=True, type=Path)
    value.add_argument("--role", choices=ROLES)
    value.add_argument("--private-bundle", type=Path)
    value.add_argument("--output", type=Path)
    value.add_argument("--inventory", type=Path)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        require_root()
        if args.action != "check-all" and args.role is None:
            fail("ARG001", "角色操作缺少 --role", "使用角色目录内的固定入口脚本。")
        if args.action == "install":
            install(args)
        elif args.action == "check":
            check(args)
        elif args.action == "diagnose":
            diagnose(args)
        else:
            check_all(args)
        return 0
    except OperatorError as exc:
        print(f"错误代码：{exc.code}\n原因：{redact(exc.reason)}\n建议：{exc.advice}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"错误代码：SYS001\n原因：{redact(str(exc))}\n建议：保留脱敏诊断日志，修复系统后用相同命令续跑。", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"错误代码：SYS999\n原因：{redact(str(exc))}\n建议：停止变更并联系发布包维护人员。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
