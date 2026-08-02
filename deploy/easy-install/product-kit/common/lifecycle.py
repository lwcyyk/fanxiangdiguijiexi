#!/usr/bin/env python3
"""域名中心单机安装生命周期核心。"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROLE_KIND = {
    "management": "management",
    "norn-a": "norn-node",
    "norn-b": "norn-node",
    "r1": "resolver-link",
    "r2": "resolver-link",
    "r3": "resolver-link",
}
REQUIRED_SECRETS = {
    "management": ("identity-issuer-ed25519-private-key", "snapshot-issuer-ed25519-private-key", "publication-ssh-identity"),
    "norn-a": ("node/config.yml", "tls/server.crt", "tls/server.key", "tls/ca.crt"),
    "norn-b": ("node/config.yml", "tls/server.crt", "tls/server.key", "tls/ca.crt"),
    "r1": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_wrapper_token", "secrets/agent_peer_token"),
    "r2": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_peer_token"),
    "r3": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_peer_token"),
}
REQUIRED_TLS_DIRS = {
    "r1": ("agent-tls", "norn-tls"), "r2": ("agent-tls", "norn-tls"), "r3": ("agent-tls", "norn-tls")
}


SENSITIVE_NAME_RE = re.compile(r"(?i)(authorization|credential|key|password|secret|token)")
SENSITIVE_QUERY_RE = re.compile(r"(?i)(api[_-]?key|authorization|credential|key|password|secret|token)")
BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s\"']+")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")


class LifecycleError(Exception):
    def __init__(self, code: str, reason: str, advice: str) -> None:
        self.code, self.reason, self.advice = code, reason, advice
        super().__init__(reason)


def die(code: str, reason: str, advice: str) -> None:
    raise LifecycleError(code, reason, advice)


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def atomic_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run(command: list[str], *, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def host_matches(expected: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", expected):
        return False
    names = {socket.gethostname().lower().rstrip("."), socket.getfqdn().lower().rstrip(".")}
    names |= {name.split(".", 1)[0] for name in names}
    expected = expected.lower().rstrip(".")
    return expected in names or expected.split(".", 1)[0] in names


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        die("CFG001", f"配置文件不存在：{path}", "先生成并安全复制本机配置目录。")
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die("CFG002", f".env 第 {number} 行格式错误", "每行使用 KEY=VALUE，禁止 shell 命令。")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            die("CFG002", f".env 键名不安全：{key}", "仅使用大写字母、数字和下划线。")
        if "$(`" in value or "`" in value or "$(" in value or "\n" in value:
            die("CFG002", f".env 值包含禁止的 shell 语法：{key}", "配置值必须是静态文本。")
        values[key] = value
    return values


def validate_images(env: dict[str, str], role: str) -> None:
    keys = {
        "management": ("RI_MANAGEMENT_IMAGE", "RI_NORN_IMAGE"),
        "norn-a": ("RI_NORN_IMAGE", "RI_NGINX_IMAGE"),
        "norn-b": ("RI_NORN_IMAGE", "RI_NGINX_IMAGE"),
        "r1": ("RI_IMAGE", "RI_KNOT_IMAGE"),
        "r2": ("RI_IMAGE", "RI_KNOT_IMAGE"),
        "r3": ("RI_IMAGE", "RI_KNOT_IMAGE"),
    }[role]
    for key in keys:
        value = env.get(key, "")
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", value) or (":late" + "st@") in value:
            die("CFG003", f"{key} 未固定完整 sha256 摘要", "使用发布清单中的精确镜像引用。")


def validate_invariants(env: dict[str, str], role: str) -> None:
    validate_images(env, role)
    if role.startswith("norn-"):
        expected = "node-a" if role == "norn-a" else "node-b"
        if env.get("RI_NORN_ROLE") != expected:
            die("SEC101", "Norn 角色与安装包不一致", "使用对应节点的专用配置。")
        if env.get("RI_NORN_NATIVE_BIND_ADDRESS") != "127.0.0.1":
            die("SEC102", "Norn 原生写接口不是仅回环绑定", "设置 RI_NORN_NATIVE_BIND_ADDRESS=127.0.0.1。")
    if role in {"r1", "r2", "r3"}:
        expected_role = "first-hop" if role == "r1" else "upstream"
        if env.get("RI_RESOLVER_ROLE") != expected_role:
            die("SEC103", "解析节点角色错误", "R1 使用 first-hop；R2/R3 使用 upstream。")
        if env.get("RI_CHAIN_ADAPTER") != "norn":
            die("SEC104", "链适配器不是 norn", "禁止回退到其他链适配器。")
        endpoints = env.get("RI_CHAIN_RPC_URLS", "").split(",")
        if len(endpoints) != 2 or any(not value.startswith("https://") for value in endpoints):
            die("SEC105", "必须配置两个 HTTPS Norn 只读端点", "使用相互独立、启用 mTLS 的只读代理。")
        if any("localhost" in value or "127.0.0.1" in value for value in endpoints):
            die("SEC105", "跨机 Norn 端点不能使用本机地址", "填写 norn-a 与 norn-b 的只读地址。")
        address = env.get("RI_MANAGEMENT_BIND_ADDRESS", "")
        if address in {"", "0.0.0.0", "::", "127.0.0.1"}:
            die("SEC106", "管理接口必须绑定专用非回环地址", "填写本机管理网地址并配合防火墙白名单。")
        if env.get("RI_TRACE_PRODUCER_UID") == env.get("RI_KNOT_RESOLVER_UID"):
            die("SEC107", "Trace Producer 与 Resolver UID 必须隔离", "分配不同的固定非特权 UID。")


def check_secret_tree(secret_dir: Path, role: str) -> None:
    if not secret_dir.is_absolute() or not secret_dir.is_dir() or secret_dir.is_symlink():
        die("SEC201", "密钥目录必须是绝对路径、真实目录且已存在", "从安全介质准备目录，不接受符号链接。")
    if secret_dir.stat().st_mode & 0o077:
        die("SEC202", "密钥目录权限宽于 0700", "执行 chmod 0700，并确保目录归属正确。")
    required = list(REQUIRED_SECRETS[role])
    for name in required:
        path = secret_dir / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            die("SEC203", f"密钥材料缺失或不安全：{name}", "提供非空普通文件，禁止符号链接和共用密钥。")
        if path.stat().st_mode & 0o077:
            die("SEC204", f"密钥文件权限宽于 0600：{name}", "执行 chmod 0600。")
    for dirname in REQUIRED_TLS_DIRS.get(role, ()):
        path = secret_dir / dirname
        if not path.is_dir() or path.is_symlink():
            die("SEC205", f"TLS 材料目录缺失：{dirname}", "为每台解析主机提供唯一 mTLS 材料。")


def disk_free_mb(path: Path) -> int:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return shutil.disk_usage(probe).free // 1024 // 1024


def preflight(args: argparse.Namespace, role_root: Path) -> dict[str, object]:
    if not host_matches(args.expected_host):
        die("HOST001", f"期望主机 {args.expected_host}，实际 {socket.gethostname()}", "把此安装包放到指定主机；禁止绕过校验。")
    if role_root.name != args.role:
        die("HOST002", "角色目录与请求角色不一致", "使用本机角色目录中的安装工具。")
    missing = [cmd for cmd in ("docker",) if shutil.which(cmd) is None]
    if missing:
        die("PRE001", f"缺少命令：{', '.join(missing)}", "离线安装 Docker Engine 和 Compose v2。")
    compose = run(["docker", "compose", "version"], capture=True, check=False)
    if compose.returncode != 0:
        die("PRE002", "Docker Compose v2 不可用", "安装 docker compose 插件并启动 Docker。")
    if disk_free_mb(args.install_root) < int(os.environ.get("DC_MIN_FREE_MB", "2048")):
        die("PRE003", "可用磁盘空间不足 2048 MiB", "清理磁盘或调整安装分区后重试。")
    if not args.config_dir or not args.config_dir.is_dir() or args.config_dir.is_symlink():
        die("PRE004", "配置目录缺失或为符号链接", "使用 --config-dir 指定渲染后的本机配置目录。")
    env = load_env(args.config_dir / ".env")
    if env.get("RI_FIELD_HOST_ID") != args.expected_host:
        die("HOST003", f"配置指定 {env.get('RI_FIELD_HOST_ID')}，安装包指定 {args.expected_host}", "重新渲染本机配置；不得修改主机校验。")
    validate_invariants(env, args.role)
    if not args.secret_dir:
        die("SEC200", "未指定密钥目录", "使用 --secret-dir 指向已通过带外方式准备的目录。")
    secret_root = args.secret_dir.resolve()
    check_secret_tree(secret_root, args.role)
    expected_secret_paths = {
        "management": {"RI_MANAGEMENT_SECRET_DIR": secret_root},
        "norn-a": {"RI_NORN_CONFIG_DIR": secret_root / "node", "RI_NORN_TLS_DIR": secret_root / "tls"},
        "norn-b": {"RI_NORN_CONFIG_DIR": secret_root / "node", "RI_NORN_TLS_DIR": secret_root / "tls"},
        "r1": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls",
               "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
        "r2": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls",
               "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
        "r3": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls",
               "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
    }[args.role]
    for key, approved in expected_secret_paths.items():
        configured = Path(env.get(key, ""))
        if not configured.is_absolute() or configured != approved:
            die("SEC206", f"{key} 未指向受检密钥目录 {approved}", "重新渲染配置；禁止从其他目录挂载密钥。")
    return {"host": args.expected_host, "role": args.role, "kind": ROLE_KIND[args.role],
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "result": "passed"}


@contextmanager
def lock(root: Path) -> Iterator[None]:
    lock_dir = root / ".install.lock"
    try:
        lock_dir.mkdir(parents=True)
    except FileExistsError:
        die("STATE001", "另一个生命周期操作正在执行", "等待其完成；确认无进程后再人工移除锁目录。")
    try:
        yield
    finally:
        lock_dir.rmdir()


def package_version(role_root: Path) -> str:
    version_file = role_root / "PACKAGE-VERSION"
    value = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "0.3.0-norn-knot-rc1"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,63}", value):
        die("PKG001", "发布版本名包含不安全字符", "重新取得可信产品包。")
    return value


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_tree_secure(source: Path, target: Path) -> None:
    if source.is_symlink():
        die("PKG002", f"拒绝复制符号链接目录：{source}", "重新生成不含符号链接的安装包。")
    shutil.copytree(source, target, symlinks=False)


def compose(target: Path, action: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    env = load_env(target / "config" / ".env")
    project = env.get("RI_FIELD_COMPOSE_PROJECT")
    if not project:
        die("CFG004", "RI_FIELD_COMPOSE_PROJECT 缺失", "重新渲染配置。")
    command = ["docker", "compose", "--project-name", project, "--env-file", str(target / "config" / ".env"),
               "-f", str(target / "docker-compose.yml"), *action]
    return run(command, capture=not check, check=check)


def set_current(root: Path, target: Path) -> None:
    temporary = root / ".current.new"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    temporary.symlink_to(target)
    os.replace(temporary, root / "current")


def install(args: argparse.Namespace, role_root: Path) -> None:
    root, state_dir = args.install_root, args.install_root / "state"
    with lock(root):
        state_file = state_dir / "install-state.json"
        state: dict[str, object] = {}
        if state_file.is_file():
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                die("STATE002", "安装状态文件损坏", "保留现场并从最近备份恢复状态文件。")
        state.update({"host": args.expected_host, "role": args.role, "status": "running"})
        atomic_json(state_file, state)
        evidence = preflight(args, role_root)
        atomic_json(state_dir / "preflight.json", evidence)
        state["preflight"] = "complete"
        atomic_json(state_file, state)
        if args.images:
            loader = role_root.parent / "common" / "load_images.py"
            run([sys.executable, str(loader), str(args.images)])
            state["images"] = "complete"
        elif state.get("images") != "complete":
            state["images"] = "not-requested"
        atomic_json(state_file, state)

        env_values = load_env(args.config_dir / ".env")
        data_dir = Path(env_values.get("RI_FIELD_DATA_DIR", ""))
        if not data_dir.is_absolute():
            die("CFG005", "RI_FIELD_DATA_DIR 必须是绝对路径", "重新渲染本机配置。")
        data_dir.mkdir(parents=True, exist_ok=True)
        marker = data_dir / ".domain-center-owned-data"
        if not marker.exists():
            atomic_text(marker, f"host={args.expected_host}\nrole={args.role}\n", 0o600)

        version = package_version(role_root)
        releases = root / "releases"
        target = releases / version
        if target.exists():
            marker = target / ".installed.json"
            if not marker.is_file():
                die("STATE003", f"发布目录已存在但无完成标记：{target}", "保留目录取证后改名，再重新执行以续跑。")
        else:
            releases.mkdir(parents=True, exist_ok=True)
            temporary = releases / f".{version}.tmp-{os.getpid()}"
            if temporary.exists():
                shutil.rmtree(temporary)
            copy_tree_secure(role_root, temporary)
            copy_tree_secure(args.config_dir, temporary / "config")
            # Secrets remain outside the immutable release and are never copied into support bundles.
            atomic_json(temporary / ".installed.json", {"host": args.expected_host, "role": args.role,
                        "version": version, "installed_at": dt.datetime.now(dt.timezone.utc).isoformat()})
            os.replace(temporary, target)
        previous = (root / "current").resolve() if (root / "current").is_symlink() else None
        set_current(root, target)
        result = compose(target, ["config", "--quiet"], check=False)
        if result.returncode != 0:
            if previous and previous.is_dir():
                set_current(root, previous)
            else:
                (root / "current").unlink(missing_ok=True)
            die("RUN001", f"Compose 静态检查失败：{result.stdout}", "修复配置后重试；程序指针已回滚，数据未删除。")
        if previous and previous != target:
            atomic_text(state_dir / "previous-release", f"{previous}\n")
        if not args.no_start:
            compose(target, ["up", "-d"])
        state.update({"status": "complete", "version": version, "release": str(target), "activated": True})
        atomic_json(state_file, state)
        print(f"安装完成：{args.role} {version}")


def status(args: argparse.Namespace) -> None:
    state_file = args.install_root / "state" / "install-state.json"
    if not state_file.is_file():
        die("STATE004", "尚无安装状态", "先执行 preflight 或 install。")
    print(state_file.read_text(encoding="utf-8"), end="")
    current = args.install_root / "current"
    if current.is_symlink() and (current / "docker-compose.yml").is_file() and shutil.which("docker"):
        result = compose(current.resolve(), ["ps"], check=False)
        if result.stdout:
            print(result.stdout, end="")


def backup(args: argparse.Namespace) -> None:
    current = args.install_root / "current"
    if not current.is_symlink():
        die("BACK001", "没有活动发布", "先完成安装。")
    env = load_env(current.resolve() / "config" / ".env")
    data = Path(env.get("RI_FIELD_DATA_DIR", ""))
    marker = data / ".domain-center-owned-data"
    if not data.is_absolute() or not marker.is_file():
        die("BACK002", "数据目录无本工具所有权标记", "禁止备份未知目录；核对 RI_FIELD_DATA_DIR。")
    output = args.output or Path.cwd() / "backup"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{args.expected_host}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(data, arcname="data", recursive=True)
    atomic_text(Path(f"{archive}.sha256"), f"{file_hash(archive)}  {archive.name}\n", 0o600)
    print(f"备份完成：{archive}")


def _redact_url(match: re.Match[str]) -> str:
    parsed = urlsplit(match.group(0))
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    netloc = f"{host}{port}"
    query = urlencode(
        [(key, "[REDACTED]" if SENSITIVE_QUERY_RE.search(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def redact_text(value: str) -> str:
    return URL_RE.sub(_redact_url, BEARER_RE.sub(r"\1[REDACTED]", value))


def redact_value(value: object, key: str = "") -> object:
    if SENSITIVE_NAME_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(child_key): redact_value(child, str(child_key)) for child_key, child in value.items()}
    if isinstance(value, list):
        return [redact_value(child) for child in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _copy_redacted_state(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(SENSITIVE_NAME_RE.search(part) for part in relative.parts) or path.is_symlink():
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(exist_ok=True)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            target.write_text(redact_text(text), encoding="utf-8")
        else:
            target.write_text(json.dumps(redact_value(parsed), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        target.chmod(0o600)


def support(args: argparse.Namespace) -> None:
    output = args.output or Path.cwd() / "support"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"support-{args.expected_host}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="domain-center-support-") as temp_name:
        temp = Path(temp_name)
        state = args.install_root / "state"
        if state.is_dir():
            _copy_redacted_state(state, temp / "state")
        atomic_text(temp / "system.txt", f"host={socket.gethostname()}\nplatform={platform.platform()}\n", 0o600)
        current = args.install_root / "current"
        if current.is_symlink() and shutil.which("docker"):
            result = compose(current.resolve(), ["ps"], check=False)
            atomic_text(temp / "compose-ps.txt", redact_text(result.stdout or ""), 0o600)
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(temp, arcname="support")
    print(f"支持包完成（不含密钥与业务数据）：{archive}")


def rollback(args: argparse.Namespace) -> None:
    root = args.install_root
    with lock(root):
        previous_file = root / "state" / "previous-release"
        if not previous_file.is_file():
            die("ROLL001", "没有记录可回滚版本", "确认至少完成过两个不同版本的安装。")
        previous = Path(previous_file.read_text(encoding="utf-8").strip())
        if not previous.is_dir() or not (previous / ".installed.json").is_file():
            die("ROLL002", "回滚版本缺失或不完整", "从可信备份恢复该发布目录。")
        current = (root / "current").resolve() if (root / "current").is_symlink() else None
        set_current(root, previous)
        check = compose(previous, ["config", "--quiet"], check=False)
        if check.returncode != 0:
            if current:
                set_current(root, current)
            die("ROLL003", "回滚目标配置检查失败", "程序指针已恢复；修复回滚目标配置后重试。")
        compose(previous, ["up", "-d"])
        if current:
            atomic_text(previous_file, f"{current}\n")
        print(f"回滚完成：{previous}")


def uninstall(args: argparse.Namespace) -> None:
    root, current = args.install_root, args.install_root / "current"
    with lock(root):
        env: dict[str, str] = {}
        if current.is_symlink():
            target = current.resolve()
            env = load_env(target / "config" / ".env")
            compose(target, ["down", "--remove-orphans"], check=False)
            current.unlink()
        if args.purge_data:
            data = Path(env.get("RI_FIELD_DATA_DIR", ""))
            marker = data / ".domain-center-owned-data"
            if not data.is_absolute() or not marker.is_file():
                die("UN001", "拒绝删除无所有权标记的数据目录", "普通卸载会保留数据；只有本工具创建的数据可清除。")
            shutil.rmtree(data)
        atomic_json(root / "state" / "install-state.json", {"host": args.expected_host, "role": args.role,
                    "status": "uninstalled", "data_purged": args.purge_data})
        print("卸载完成；密钥目录和历史发布未删除。" if not args.purge_data else "卸载完成；已清除本工具拥有的数据。")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="域名中心主机生命周期工具")
    value.add_argument("action", choices=("preflight", "install", "status", "support", "backup", "rollback", "uninstall"))
    value.add_argument("--role", required=True, choices=tuple(ROLE_KIND))
    value.add_argument("--expected-host", required=True)
    value.add_argument("--install-root", required=True, type=Path)
    value.add_argument("--config-dir", type=Path)
    value.add_argument("--secret-dir", type=Path)
    value.add_argument("--images", type=Path)
    value.add_argument("--output", type=Path)
    value.add_argument("--yes", action="store_true")
    value.add_argument("--purge-data", action="store_true")
    value.add_argument("--no-start", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        role_root = Path(__file__).resolve().parent.parent / args.role
        if args.action in {"install", "rollback", "uninstall"} and not args.yes:
            die("ARG001", "危险操作缺少 --yes", "确认变更窗口后显式传入 --yes。")
        if args.action in {"preflight", "install"}:
            evidence = preflight(args, role_root)
            if args.action == "preflight":
                atomic_json(args.install_root / "state" / "preflight.json", evidence)
                print("预检通过。")
            else:
                install(args, role_root)
        elif args.action == "status": status(args)
        elif args.action == "support": support(args)
        elif args.action == "backup": backup(args)
        elif args.action == "rollback": rollback(args)
        elif args.action == "uninstall": uninstall(args)
        return 0
    except LifecycleError as exc:
        print(f"错误代码：{exc.code}\n原因：{exc.reason}\n建议：{exc.advice}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"错误代码：SYS001\n原因：系统操作失败：{exc}\n建议：保留安装状态和支持包，修复系统后用相同命令续跑。", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"错误代码：SYS999\n原因：未预期错误：{exc}\n建议：停止变更并联系发布包维护人员。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
