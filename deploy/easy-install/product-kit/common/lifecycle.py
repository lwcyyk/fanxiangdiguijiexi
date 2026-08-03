#!/usr/bin/env python3
"""域名中心单机安装生命周期核心（仅使用 Python 标准库）。"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Iterator, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import uuid

try:
    from key_material import KeyMaterialError, validate_management_keys
except ImportError as exc:  # pragma: no cover - product-kit dependency error
    KeyMaterialError = ValueError
    validate_management_keys = None
    _KEY_MATERIAL_IMPORT_ERROR = exc
else:
    _KEY_MATERIAL_IMPORT_ERROR = None

ROLE_KIND = {
    "management": "management", "norn-a": "norn-node", "norn-b": "norn-node",
    "r1": "resolver-link", "r2": "resolver-link", "r3": "resolver-link",
}
REQUIRED_SECRETS = {
    "management": ("identity-issuer-ed25519-private-key", "snapshot-issuer-ed25519-private-key", "publication-ssh-identity"),
    "norn-a": ("node/config.yml", "tls/server.crt", "tls/server.key", "tls/ca.crt"),
    "norn-b": ("node/config.yml", "tls/server.crt", "tls/server.key", "tls/ca.crt"),
    "r1": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_wrapper_token", "secrets/agent_peer_token"),
    "r2": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_wrapper_token", "secrets/agent_peer_token"),
    "r3": ("secrets/agent_private_key", "secrets/trace_ingest_token", "secrets/agent_wrapper_token", "secrets/agent_peer_token"),
}
RESOLVER_TLS_FILES = {
    "agent-tls": (
        "agent.crt", "agent.key", "client-ca.crt", "agent-client.crt", "agent-client.key",
        "agent-ca.crt", "trace-client.crt", "trace-client.key",
    ),
    "norn-tls": ("ca.crt", "client.crt", "client.key"),
}
R1_TLS_FILES = ("wrapper-client.crt", "wrapper-client.key")
TLS_KEY_SUFFIXES = (".key",)
DATA_MARKER = ".domain-center-owned-data.json"
STATE_SCHEMA = "domain-center-install-state-v2"

SENSITIVE_NAME_RE = re.compile(r"(?i)(authorization|cookie|credential|key|password|passwd|secret|token)")
SENSITIVE_QUERY_RE = re.compile(r"(?i)(api[_-]?key|authorization|cookie|credential|key|password|passwd|secret|token)")
AUTH_RE = re.compile(r"(?im)\b(authorization\s*[:=]\s*)?(bearer|basic)\s+[^\s\"']+")
COOKIE_RE = re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).*$")
ASSIGNMENT_RE = re.compile(r"(?im)^(\s*[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)[A-Za-z0-9_.-]*\s*[:=]\s*)(.*)$")
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])")
PEM_PRIVATE_RE = re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----", re.DOTALL)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
RESIDUAL_RE = re.compile(
    r"(?im)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----|\b(?:bearer|basic)\s+(?!\[REDACTED\])\S+|"
    r"^\s*(?:authorization|cookie|password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(?!\[REDACTED\])\S+|"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
)


class LifecycleError(Exception):
    def __init__(self, code: str, reason: str, advice: str) -> None:
        self.code, self.reason, self.advice = code, reason, advice
        super().__init__(reason)


def die(code: str, reason: str, advice: str) -> NoReturn:
    raise LifecycleError(code, reason, advice)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


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
    return subprocess.run(
        command, check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def safe_host(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", normalized):
        die("HOST000", f"主机名不合法：{value!r}", "使用完整规范主机名或明确的短主机名。")
    return normalized


def local_host_names() -> set[str]:
    return {safe_host(value) for value in (socket.gethostname(), socket.getfqdn()) if value}


def host_matches(expected: str, actual_names: set[str] | None = None) -> bool:
    expected = safe_host(expected)
    names = {safe_host(value) for value in (actual_names or local_host_names())}
    if "." not in expected:
        names |= {value.split(".", 1)[0] for value in names}
    return expected in names


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file() or path.is_symlink():
        die("CFG001", f"配置文件不存在或不安全：{path}", "先生成并安全复制本机配置目录。")
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die("CFG002", f".env 第 {number} 行格式错误", "每行使用 KEY=VALUE，禁止 shell 命令。")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            die("CFG002", f".env 键名不安全：{key}", "仅使用大写字母、数字和下划线。")
        if "`" in value or "$(" in value or "\n" in value:
            die("CFG002", f".env 值包含禁止的 shell 语法：{key}", "配置值必须是静态文本。")
        values[key] = value.strip("'\"")
    return values


def validate_images(env: dict[str, str], role: str) -> None:
    keys = {
        "management": ("RI_MANAGEMENT_IMAGE", "RI_NORN_IMAGE"),
        "norn-a": ("RI_NORN_IMAGE", "RI_NGINX_IMAGE"), "norn-b": ("RI_NORN_IMAGE", "RI_NGINX_IMAGE"),
        "r1": ("RI_IMAGE", "RI_KNOT_IMAGE"), "r2": ("RI_IMAGE", "RI_KNOT_IMAGE"), "r3": ("RI_IMAGE", "RI_KNOT_IMAGE"),
    }[role]
    for key in keys:
        value = env.get(key, "")
        if not re.fullmatch(r"[^\s@]+:ri-[0-9a-f]{16}", value) or (":late" + "st") in value.lower() or "localhost" in value.lower() or "127.0.0.1" in value:
            die("CFG003", f"{key} 未使用离线清单固定的本地标签", "使用包内 image-lock.json 对应的确定性导入标签；不得 pull。")


def _validate_wrapper_upstreams(env: dict[str, str]) -> None:
    raw = env.get("RI_WRAPPER_UPSTREAMS", "")
    if not raw.strip():
        die("SEC108", "R1 Wrapper 未配置上游", "提供独立 R1 上游解析器地址；不得指向 Wrapper 本身。")
    bind = env.get("DNS_BIND_ADDRESS", "").strip().lower().rstrip(".")
    local_names = {name.lower().rstrip(".") for name in local_host_names()}
    local_ips = _local_ips()
    for item in raw.split(","):
        value = item.strip()
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        try:
            parsed_port = parsed.port
        except ValueError:
            die("SEC108", f"R1 Wrapper 上游端口无效：{value}", "使用 udp://host:53,tcp://host:53 格式。")
        if parsed.scheme not in {"udp", "tcp"} or not host or parsed_port is None:
            die("SEC108", f"R1 Wrapper 上游格式无效：{value}", "使用 udp://host:53,tcp://host:53 格式。")
        if host in {"localhost", "localhost.localdomain"} or host in local_names or host in local_ips:
            die("SEC108", "R1 Wrapper 上游指向本机，可能形成 DNS 环路", "将上游改为独立 R1/真实解析器地址。")
        if bind and host == bind:
            die("SEC108", "R1 Wrapper 上游指向自身 bind/VIP", "将上游改为独立 R1/真实解析器地址。")
        if parsed_port == 1053:
            die("SEC108", "R1 Wrapper 上游指向 shadow 1053 端口", "上游必须使用独立解析器服务端口。")


def validate_invariants(env: dict[str, str], role: str) -> None:
    validate_images(env, role)
    if role == "r1":
        _validate_wrapper_upstreams(env)
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


def _validate_management_secret_material(secret_dir: Path) -> dict[str, dict[str, str]]:
    if secret_dir.stat().st_uid != 0 or secret_dir.stat().st_gid != 0:
        die("SEC215", "Management 密钥目录归属必须为 root:root", "由 root 创建专用密钥目录并设置归属 root:root。")
    for name in REQUIRED_SECRETS["management"]:
        path = secret_dir / name
        if path.stat().st_uid != 0 or path.stat().st_gid != 0:
            die("SEC215", f"Management 密钥文件归属必须为 root:root：{name}", "由 root 安全复制密钥并设置归属 root:root。")
    if validate_management_keys is None:
        die("SEC211", "缺少 cryptography，无法解析 Management 密钥", "安装包运行时必须提供项目锁定的 cryptography 依赖。")
    try:
        return validate_management_keys(secret_dir)
    except KeyMaterialError as exc:
        message = str(exc)
        if "distinct" in message or "reuse" in message:
            die("SEC214", f"Management 密钥用途隔离失败：{message}", "为三个用途提供相互独立的 Ed25519 私钥。")
        if "not a non-empty" in message:
            die("SEC203", "Management 密钥材料缺失或不安全", "提供非空普通文件，禁止符号链接。")
        if "permissions must be 0600" in message:
            die("SEC204", "Management 密钥文件权限不是 0600", "执行 chmod 0600。")
        die("SEC212", f"Management 密钥格式或算法无效：{message}", "issuer 使用未加密 PKCS#8 PEM Ed25519；publication 使用未加密 OpenSSH Ed25519。")


def _restricted_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        die("SEC203", f"密钥材料缺失或不安全：{label}", "提供非空普通文件，禁止符号链接和共用密钥。")
    if path.stat().st_mode & 0o077:
        die("SEC204", f"密钥文件权限宽于 0600：{label}", "执行 chmod 0600。")


def _openssl_public(path: Path, certificate: bool) -> bytes:
    command = ["openssl", "x509", "-in", str(path), "-pubkey", "-noout"] if certificate else ["openssl", "pkey", "-in", str(path), "-pubout"]
    result = run(command, capture=True, check=False)
    if result.returncode != 0:
        die("SEC207", f"无法解析 TLS {'证书' if certificate else '私钥'}：{path.name}", "重新签发并安全复制 PEM 材料。")
    return (result.stdout or "").encode()


def _match_tls_pair(directory: Path, stem: str) -> None:
    cert, key = directory / f"{stem}.crt", directory / f"{stem}.key"
    if _openssl_public(cert, True) != _openssl_public(key, False):
        die("SEC208", f"TLS 证书与私钥不匹配：{stem}", "提供同一 CSR 签发的证书和私钥。")


def _validate_certificate(path: Path) -> None:
    try:
        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
        not_after = decoded.get("notAfter")
        if not isinstance(not_after, str) or ssl.cert_time_to_seconds(not_after) <= time.time():
            raise ValueError("certificate expired or missing notAfter")
    except (OSError, ValueError, ssl.SSLError) as exc:
        die("SEC207", f"TLS 证书无效或已过期：{path.name}（{exc}）", "重新签发有效 PEM 证书。")


def _unsafe_secret_root(path: Path, install_root: Path | None = None) -> bool:
    absolute = path.absolute()
    forbidden = {Path("/"), Path("/etc"), Path("/var"), Path("/home"), Path("/opt")}
    if install_root is not None:
        install = install_root.absolute()
        forbidden |= {install, install / "data", install / "releases", install / "state"}
    if absolute in forbidden:
        return True
    probe = absolute
    while probe != probe.parent:
        if probe.exists() and probe.is_symlink():
            return True
        probe = probe.parent
    return False


def check_secret_tree(secret_dir: Path, role: str, install_root: Path | None = None) -> None:
    if not secret_dir.is_absolute() or not secret_dir.is_dir() or _unsafe_secret_root(secret_dir, install_root):
        die("SEC201", "密钥目录必须是专用绝对真实目录，不能是广泛目录或经过符号链接", "从安全介质准备独立目录。")
    if secret_dir.stat().st_mode & 0o077:
        die("SEC202", "密钥目录权限宽于 0700", "执行 chmod 0700，并确保目录归属正确。")
    for name in REQUIRED_SECRETS[role]:
        _restricted_file(secret_dir / name, name)
    if role == "management":
        _validate_management_secret_material(secret_dir)
    if role in {"r1", "r2", "r3"}:
        for dirname, names in RESOLVER_TLS_FILES.items():
            directory = secret_dir / dirname
            if not directory.is_dir() or directory.is_symlink() or directory.stat().st_mode & 0o077:
                die("SEC205", f"TLS 材料目录缺失或权限不安全：{dirname}", "为每台解析主机提供唯一 mTLS 材料并 chmod 0700。")
            required = names + (R1_TLS_FILES if role == "r1" and dirname == "agent-tls" else ())
            for name in required:
                _restricted_file(directory / name, f"{dirname}/{name}")
                if name.endswith(".crt"):
                    _validate_certificate(directory / name)
        if not shutil.which("openssl"):
            die("SEC207", "缺少 openssl，无法验证 TLS 证书与私钥匹配", "离线安装 openssl 后重试。")
        for stem in ("agent", "agent-client", "trace-client") + (("wrapper-client",) if role == "r1" else ()):
            _match_tls_pair(secret_dir / "agent-tls", stem)
        _match_tls_pair(secret_dir / "norn-tls", "client")
        values = [(secret_dir / name).read_bytes().strip() for name in REQUIRED_SECRETS[role] if "token" in name]
        if len(values) != len(set(values)):
            die("SEC209", "同一主机的 Token 必须相互独立", "重新安全生成每个用途独立的随机 Token。")


def disk_free_mb(path: Path) -> int:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return shutil.disk_usage(probe).free // 1024 // 1024


def _check(status: bool, check_id: str, message: str, *, required: bool = True, details: object = None) -> dict[str, object]:
    return {
        "check_id": check_id, "status": "passed" if status else "failed",
        "status_zh": "通过" if status else "失败", "message_zh": message,
        "required": required, "details": details,
    }


def _os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip("\"")
    except OSError:
        pass
    return values


def _ntp_synchronized() -> bool:
    if shutil.which("timedatectl"):
        result = run(["timedatectl", "show", "--property=NTPSynchronized", "--value"], capture=True, check=False)
        if result.returncode == 0:
            return (result.stdout or "").strip().lower() == "yes"
    marker = Path("/run/systemd/timesync/synchronized")
    return marker.exists() and time.time() - marker.stat().st_mtime < 7 * 86400


def _firewall_present() -> tuple[bool, str]:
    if shutil.which("ufw"):
        result = run(["ufw", "status"], capture=True, check=False)
        return result.returncode == 0 and "status: active" in (result.stdout or "").lower(), "ufw"
    if shutil.which("nft"):
        result = run(["nft", "list", "ruleset"], capture=True, check=False)
        return result.returncode == 0 and bool((result.stdout or "").strip()), "nftables"
    return False, "none"


def _security_module() -> tuple[bool, str]:
    apparmor = Path("/sys/module/apparmor/parameters/enabled")
    if apparmor.is_file():
        return apparmor.read_text(encoding="ascii", errors="ignore").strip().lower().startswith("y"), "apparmor"
    enforce = Path("/sys/fs/selinux/enforce")
    if enforce.is_file():
        return enforce.read_text(encoding="ascii", errors="ignore").strip() == "1", "selinux"
    return False, "none"


def _local_ips() -> set[str]:
    values = {"127.0.0.1", "::1"}
    for host in (socket.gethostname(), socket.getfqdn()):
        try:
            values |= {item[4][0] for item in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            pass
    return values


def _machine_id() -> str:
    path = Path("/etc/machine-id")
    if not path.is_file() or path.is_symlink():
        die("HOST005", "无法安全读取 /etc/machine-id", "确认主机 machine-id 是普通文件后重试。")
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        die("HOST005", "主机 machine-id 格式无效", "恢复 32 位小写十六进制 machine-id 后重试。")
    return value


def _validate_machine_identity(metadata: dict[str, object]) -> None:
    expected = metadata.get("machine_id")
    if expected is None:
        return
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{32}", expected):
        die("HOST005", "安装包 machine-id 格式无效", "重新取得绑定本机 machine-id 的安装包。")
    if _machine_id() != expected:
        die("HOST006", "当前主机 machine-id 与安装包不一致", "把安装包放到绑定的主机；禁止绕过身份校验。")


def _package_metadata(role_root: Path) -> dict[str, object]:
    path = role_root.parent.parent / "expected-host.json"
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die("PKG003", f"expected-host.json 无法解析：{exc}", "重新取得可信主机包。")
    if not isinstance(value, dict):
        die("PKG003", "expected-host.json 顶层不是对象", "重新取得可信主机包。")
    return value


def _port_specs(env: dict[str, str], role: str) -> list[tuple[str, int, str]]:
    if role in {"r1", "r2", "r3"}:
        specs = [
            (env.get("RI_RESOLVER_BIND_ADDRESS", ""), 53, "udp"),
            (env.get("RI_RESOLVER_BIND_ADDRESS", ""), 53, "tcp"),
            (env.get("RI_MANAGEMENT_BIND_ADDRESS", ""), 8443, "tcp"),
            (env.get("RI_MANAGEMENT_BIND_ADDRESS", ""), 9109, "tcp"),
            (env.get("RI_MANAGEMENT_BIND_ADDRESS", ""), 9110, "tcp"),
        ]
        if role == "r1":
            specs += [(env.get("DNS_BIND_ADDRESS", ""), 1053, "udp"),
                      (env.get("DNS_BIND_ADDRESS", ""), 1053, "tcp"),
                      (env.get("RI_MANAGEMENT_BIND_ADDRESS", ""), 9108, "tcp")]
        return specs
    if role.startswith("norn-"):
        return [
            (env.get("RI_NORN_NATIVE_BIND_ADDRESS", ""), int(env.get("RI_NORN_NATIVE_LOOPBACK_PORT", "0")), "tcp"),
            (env.get("RI_NORN_P2P_BIND_ADDRESS", ""), 31258, "tcp"),
            (env.get("RI_NORN_READ_BIND_ADDRESS", ""), int(env.get("RI_NORN_READ_PORT", "8443")), "tcp"),
        ]
    return []


def _ports_available(specs: list[tuple[str, int, str]]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    for address, port, protocol in specs:
        if not address or not port:
            failures.append(f"{address or '<missing>'}:{port}/{protocol}")
            continue
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        sock = socket.socket(family, kind)
        try:
            sock.bind((address, port))
        except OSError:
            failures.append(f"{address}:{port}/{protocol}")
        finally:
            sock.close()
    return not failures, failures


def preflight(args: argparse.Namespace, role_root: Path) -> dict[str, object]:
    expected = safe_host(args.expected_host)
    if not host_matches(expected):
        die("HOST001", f"期望主机 {expected}，实际 {socket.gethostname()}", "把此安装包放到指定主机；禁止绕过校验。")
    if role_root.name != args.role:
        die("HOST002", "角色目录与请求角色不一致", "使用本机角色目录中的安装工具。")
    if not args.config_dir or not args.config_dir.is_dir() or args.config_dir.is_symlink():
        die("PRE004", "配置目录缺失或为符号链接", "使用 --config-dir 指定渲染后的本机配置目录。")
    env = load_env(args.config_dir / ".env")
    if safe_host(env.get("RI_FIELD_HOST_ID", "")) not in {expected, expected.split(".", 1)[0]}:
        die("HOST003", f"配置指定 {env.get('RI_FIELD_HOST_ID')}，安装包指定 {expected}", "重新渲染本机配置；不得修改主机校验。")
    metadata = _package_metadata(role_root)
    if metadata:
        packaged_host = safe_host(str(metadata.get("expected_host") or metadata.get("hostname") or ""))
        declared_hostname = safe_host(str(metadata.get("hostname") or ""))
        declared_fqdn = metadata.get("fqdn")
        valid_hosts = {packaged_host, declared_hostname}
        if isinstance(declared_fqdn, str):
            valid_hosts.add(safe_host(declared_fqdn))
        if expected not in valid_hosts:
            die("HOST004", "expected-host.json 与请求主机不一致", "重新取得此主机专用安装包。")
        if metadata.get("role") != args.role:
            die("HOST004", "expected-host.json 与请求角色不一致", "重新取得此主机专用安装包。")
        _validate_machine_identity(metadata)
    validate_invariants(env, args.role)
    if not args.secret_dir:
        die("SEC200", "未指定密钥目录", "使用 --secret-dir 指向已通过带外方式准备的目录。")
    if args.secret_dir.is_symlink():
        die("SEC201", "密钥目录不能是符号链接", "使用本机真实目录。")
    secret_root = args.secret_dir.absolute()
    check_secret_tree(secret_root, args.role, args.install_root)
    expected_secret_paths = {
        "management": {"RI_MANAGEMENT_SECRET_DIR": secret_root},
        "norn-a": {"RI_NORN_CONFIG_DIR": secret_root / "node", "RI_NORN_TLS_DIR": secret_root / "tls"},
        "norn-b": {"RI_NORN_CONFIG_DIR": secret_root / "node", "RI_NORN_TLS_DIR": secret_root / "tls"},
        "r1": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls", "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
        "r2": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls", "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
        "r3": {"RI_RESOLVER_SECRET_DIR": secret_root / "secrets", "RI_AGENT_TLS_DIR": secret_root / "agent-tls", "RI_NORN_CLIENT_TLS_DIR": secret_root / "norn-tls"},
    }[args.role]
    for key, approved in expected_secret_paths.items():
        configured = Path(env.get(key, ""))
        if not configured.is_absolute() or configured != approved:
            die("SEC206", f"{key} 未指向受检密钥目录 {approved}", "重新渲染配置；禁止从其他目录挂载密钥。")

    release = _os_release()
    firewall_ok, firewall = _firewall_present()
    security_ok, security = _security_module()
    checks = [
        _check(release.get("ID") == "ubuntu" and release.get("VERSION_ID") in {"22.04", "24.04"}, "machine.os", "Ubuntu 22.04/24.04", details=release),
        _check(platform.machine().lower() in {"amd64", "x86_64"}, "machine.arch", "amd64 架构", details=platform.machine()),
        _check(bool(Path("/sys/fs/cgroup/cgroup.controllers").is_file() or Path("/proc/cgroups").is_file()), "machine.cgroup", "cgroup 可用"),
        _check(_ntp_synchronized(), "machine.ntp", "系统时间已同步"),
        _check(firewall_ok, "machine.firewall", "基础防火墙策略已启用", details=firewall),
        _check(security_ok, "machine.security_module", "AppArmor/SELinux 强制模块已启用", details=security),
        _check(disk_free_mb(args.install_root) >= int(os.environ.get("DC_MIN_FREE_MB", "2048")), "resource.disk", "磁盘空间满足要求"),
        _check((os.cpu_count() or 0) >= int(os.environ.get("DC_MIN_CPUS", "2")), "resource.cpu", "CPU 数满足要求", details=os.cpu_count()),
    ]
    try:
        memory_mb = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))) // 1024
    except (OSError, StopIteration, ValueError):
        memory_mb = 0
    checks.append(_check(memory_mb >= int(os.environ.get("DC_MIN_MEMORY_MB", "2048")), "resource.memory", "内存满足要求", details=memory_mb))
    expected_ips: list[str] = []
    for key in ("expected_ips", "ip_addresses", "ips"):
        if isinstance(metadata.get(key), list):
            expected_ips.extend(str(value) for value in metadata[key])
    if isinstance(metadata.get("management_ip"), str):
        expected_ips.append(str(metadata["management_ip"]))
    checks.append(_check(not expected_ips or bool(set(expected_ips) & _local_ips()), "machine.ip", "本机 IP 与主机包一致", required=bool(expected_ips), details=expected_ips or "manifest-not-specified"))
    active = (args.install_root / "current").is_symlink()
    ports_ok, occupied = (True, []) if active else _ports_available(_port_specs(env, args.role))
    checks.append(_check(ports_ok, "machine.ports", "角色所需端口可绑定", details=occupied))
    docker = shutil.which("docker") is not None
    checks.append(_check(docker, "docker.command", "Docker 命令可用"))
    daemon = False
    compose_ok = False
    daemon_output = "not-run"
    compose_output = "not-run"
    if docker:
        daemon_result = run(["docker", "version"], capture=True, check=False)
        compose_result = run(["docker", "compose", "version"], capture=True, check=False)
        daemon = daemon_result.returncode == 0
        compose_ok = compose_result.returncode == 0
        daemon_output = redact_text((daemon_result.stdout or "")[-1000:])
        compose_output = redact_text((compose_result.stdout or "")[-1000:])
    checks += [
        _check(daemon, "docker.daemon", "Docker daemon 可用", details=daemon_output),
        _check(compose_ok, "docker.compose", "Docker Compose v2 可用", details=compose_output),
    ]
    evidence = {
        "host": expected, "role": args.role, "kind": ROLE_KIND[args.role], "checked_at": now(),
        "result": "passed" if all(item["status"] == "passed" or not item["required"] for item in checks) else "failed",
        "status_zh": "通过" if all(item["status"] == "passed" or not item["required"] for item in checks) else "失败",
        "checks": checks,
    }
    atomic_json(args.install_root / "state" / "preflight.json", evidence)
    failed = [str(item["check_id"]) for item in checks if item["required"] and item["status"] != "passed"]
    if failed:
        die("PRE010", f"必需机器检查失败：{', '.join(failed)}", "查看 preflight.json，修复全部 required 检查后重试。")
    return evidence


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


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            die("PKG002", f"目录含符号链接：{path}", "重新生成不含符号链接的安装包。")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(b"\0")
            digest.update(file_hash(path).encode())
            digest.update(b"\n")
    return digest.hexdigest()


def copy_tree_secure(source: Path, target: Path) -> None:
    tree_hash(source)
    shutil.copytree(source, target, symlinks=False)


def compose(target: Path, action: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    env = load_env(target / "config" / ".env")
    project = env.get("RI_FIELD_COMPOSE_PROJECT")
    if not project:
        die("CFG004", "RI_FIELD_COMPOSE_PROJECT 缺失", "重新渲染配置。")
    command = ["docker", "compose", "--project-name", project, "--env-file", str(target / "config" / ".env"), "-f", str(target / "docker-compose.yml"), *action]
    return run(command, capture=not check, check=check)


def set_current(root: Path, target: Path) -> None:
    temporary = root / ".current.new"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, root / "current")


def _phase(state: dict[str, object], state_file: Path, name: str, digest: str = "") -> None:
    phases = state.setdefault("phases", {})
    assert isinstance(phases, dict)
    phases[name] = {"status": "complete", "status_zh": "完成", "completed_at": now(), "input_sha256": digest}
    atomic_json(state_file, state)


def _http_ready(url: str, context: ssl.SSLContext | None = None) -> bool:
    try:
        with urlopen(Request(url, headers={"User-Agent": "domain-center-readiness/1"}), timeout=3, context=context) as response:
            return 200 <= response.status < 300
    except (OSError, HTTPError, URLError):
        return False


class _NornProbeError(Exception):
    def __init__(self, code: str, reason: str, advice: str, *, retryable: bool) -> None:
        self.code, self.reason, self.advice, self.retryable = code, reason, advice, retryable
        super().__init__(reason)


def _norn_probe_error(code: str, reason: str, advice: str, *, retryable: bool) -> NoReturn:
    raise _NornProbeError(code, reason, advice, retryable=retryable)


def _grpc_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 64:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应的 protobuf 编码无效", "确认只读 Norn 服务返回合法的 GetBlockNumber 响应。", retryable=False)


def _validate_norn_block_number(body: bytes) -> None:
    if len(body) < 5 or body[0] != 0:
        _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应帧无效", "确认只读 Norn 服务返回未压缩的合法 gRPC 响应。", retryable=False)
    length = int.from_bytes(body[1:5], "big")
    payload = body[5:]
    if length != len(payload):
        _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应长度不一致", "确认只读 Norn 服务返回完整的 GetBlockNumber 响应。", retryable=False)
    offset = 0
    number: int | None = None
    while offset < len(payload):
        key, offset = _grpc_varint(payload, offset)
        field, wire = key >> 3, key & 7
        if field == 2 and wire == 0:
            if number is not None:
                _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应包含重复区块高度", "确认只读 Norn 服务的响应 schema 未改变。", retryable=False)
            number, offset = _grpc_varint(payload, offset)
        elif wire == 0:
            _, offset = _grpc_varint(payload, offset)
        elif wire == 1:
            offset += 8
        elif wire == 2:
            size, offset = _grpc_varint(payload, offset)
            offset += size
        elif wire == 5:
            offset += 4
        else:
            _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应包含未知 protobuf wire type", "确认只读 Norn 服务返回合法的 GetBlockNumber 响应。", retryable=False)
        if offset > len(payload):
            _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC protobuf 响应被截断", "确认只读 Norn 服务返回完整响应。", retryable=False)
    if number is None:
        _norn_probe_error("NORN_GRPC_INVALID", "Norn gRPC 响应缺少区块高度", "确认只读 Norn 服务返回 GetBlockNumber 的 number 字段。", retryable=False)


def _norn_grpc_ready(env: dict[str, str], secret_dir: Path | None) -> None:
    tls_dir = secret_dir / "norn-tls" if secret_dir else None
    if tls_dir is None:
        _norn_probe_error("NORN_TLS_MISSING", "Norn mTLS 密钥目录缺失", "提供受检的 norn-tls/ca.crt、client.crt 和 client.key。", retryable=False)
    material = {name: tls_dir / name for name in ("ca.crt", "client.crt", "client.key")}
    for name, path in material.items():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            _norn_probe_error("NORN_TLS_MISSING", f"Norn mTLS 材料缺失：{name}", "提供受检的 norn-tls/ca.crt、client.crt 和 client.key。", retryable=False)
    try:
        context = ssl.create_default_context(cafile=str(material["ca.crt"]))
    except (OSError, ssl.SSLError, ValueError) as exc:
        _norn_probe_error("NORN_TLS_CA_INVALID", f"Norn mTLS CA 无效：{type(exc).__name__}", "提供有效的 PEM CA 证书。", retryable=False)
    try:
        context.load_cert_chain(str(material["client.crt"]), str(material["client.key"]))
    except (OSError, ssl.SSLError, ValueError) as exc:
        _norn_probe_error("NORN_TLS_CERT_KEY_MISMATCH", f"Norn mTLS 客户端证书或私钥无效：{type(exc).__name__}", "提供匹配的 client.crt 和 client.key。", retryable=False)
    try:
        hostname = safe_host(env.get("RI_NORN_READ_HOSTNAME", ""))
        port = int(env.get("RI_NORN_READ_PORT", "8443"))
    except (LifecycleError, ValueError):
        _norn_probe_error("NORN_CONNECTION", "Norn 只读端点配置无效", "配置有效的 Norn HTTPS 主机名和端口。", retryable=False)
    url = f"https://{hostname}:{port}/Blockchain/GetBlockNumber"
    request = Request(
        url,
        data=b"\x00\x00\x00\x00\x00",
        method="POST",
        headers={
            "Content-Type": "application/grpc",
            "TE": "trailers",
            "User-Agent": "domain-center-readiness/1",
        },
    )
    try:
        with urlopen(request, timeout=3, context=context) as response:
            status = response.status if hasattr(response, "status") else response.getcode()
            content_type = response.headers.get("Content-Type", "")
            grpc_status = response.headers.get("grpc-status")
            body = response.read(4 * 1024 * 1024 + 1)
    except HTTPError as exc:
        _norn_probe_error("NORN_HTTP_REJECTED", f"Norn 只读端点拒绝请求（HTTP {exc.code}）", "确认只读代理、客户端证书和 Norn 服务状态。", retryable=exc.code >= 500)
    except (OSError, URLError, TimeoutError) as exc:
        _norn_probe_error("NORN_CONNECTION", f"无法连接 Norn 只读端点（{type(exc).__name__}）", "确认 Norn 只读代理运行且网络可达。", retryable=True)
    if not 200 <= status < 300 or not content_type.lower().startswith("application/grpc") or grpc_status != "0":
        _norn_probe_error("NORN_HTTP_REJECTED", f"Norn gRPC 响应被拒绝（HTTP {status}，grpc-status {grpc_status or 'missing'}）", "确认只读代理返回 HTTP 2xx 和 grpc-status 0。", retryable=status >= 500)
    _validate_norn_block_number(body)


def _dns_query(address: str, port: int, tcp: bool) -> bool:
    query_id = secrets.randbelow(65536)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        if tcp:
            sock.connect((address, port))
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", sock.recv(2))[0]
            response = b""
            while len(response) < length:
                response += sock.recv(length - len(response))
        else:
            sock.sendto(packet, (address, port))
            response = sock.recv(4096)
        return len(response) >= 12 and struct.unpack("!H", response[:2])[0] == query_id and (response[3] & 0x0F) != 2
    except OSError:
        return False
    finally:
        sock.close()


def readiness_probe(role: str, phase: str, env: dict[str, str], secret_dir: Path | None) -> bool:
    address = env.get("RI_MANAGEMENT_BIND_ADDRESS", "127.0.0.1")
    if phase == "registry_ready":
        return _http_ready(f"http://{address}:9109/readyz")
    if phase == "agent_trace_ready":
        context = ssl.create_default_context(cafile=str(secret_dir / "agent-tls" / "agent-ca.crt") if secret_dir else None)
        if secret_dir:
            context.load_cert_chain(str(secret_dir / "agent-tls" / "agent-client.crt"), str(secret_dir / "agent-tls" / "agent-client.key"))
        return _http_ready(f"https://{safe_host(env.get('RI_FIELD_HOST_ID', ''))}:8443/readyz", context) and _http_ready(f"http://{address}:9110/readyz")
    if phase == "resolver_ready":
        resolver = env.get("RI_RESOLVER_BIND_ADDRESS", "")
        return _dns_query(resolver, 53, False) and _dns_query(resolver, 53, True)
    if phase == "wrapper_shadow_ready":
        bind = env.get("DNS_BIND_ADDRESS", "")
        port = 1053
        return port == 1053 and _http_ready(f"http://{address}:9108/readyz") and _dns_query(bind, port, False) and _dns_query(bind, port, True)
    if phase == "norn_ready":
        _norn_grpc_ready(env, secret_dir)
        return True
    return True


def _wait_readiness(role: str, phase: str, env: dict[str, str], secret_dir: Path | None) -> None:
    deadline = time.monotonic() + int(os.environ.get("DC_READINESS_TIMEOUT_SECONDS", "60"))
    last_probe_error: _NornProbeError | None = None
    while time.monotonic() < deadline:
        try:
            if readiness_probe(role, phase, env, secret_dir):
                return
        except _NornProbeError as exc:
            last_probe_error = exc
            if not exc.retryable:
                die(exc.code, exc.reason, exc.advice)
        time.sleep(1)
    if last_probe_error is not None:
        die(last_probe_error.code, last_probe_error.reason, last_probe_error.advice)
    die("RUN002", f"应用 readiness 超时：{phase}", "禁止标记安装完成；修复服务后重试，程序指针已回滚。")


def start_ordered(target: Path, role: str, env: dict[str, str], secret_dir: Path | None, state: dict[str, object], state_file: Path) -> None:
    if role in {"r1", "r2", "r3"}:
        sequence = [
            ("registry_ready", ["up", "-d", "registry-sync"]),
            ("agent_trace_ready", ["up", "-d", "agent", "trace-adapter"]),
            ("resolver_ready", ["up", "-d", "trace-producer", "resolver"]),
        ]
        if role == "r1":
            sequence.append(("wrapper_shadow_ready", ["--profile", "first-hop", "up", "-d", "wrapper"]))
        phases = state.get("phases", {})
        for phase_name, action in sequence:
            if isinstance(phases, dict) and phase_name in phases and readiness_probe(role, phase_name, env, secret_dir):
                continue
            compose(target, action)
            _wait_readiness(role, phase_name, env, secret_dir)
            _phase(state, state_file, phase_name, hashlib.sha256(" ".join(action).encode()).hexdigest())
    elif role.startswith("norn-"):
        compose(target, ["up", "-d", "norn-node"])
        compose(target, ["up", "-d", "norn-read-proxy"])
        _wait_readiness(role, "norn_ready", env, secret_dir)
        _phase(state, state_file, "norn_ready")
    else:
        compose(target, ["--profile", "tools", "up", "-d", "management-tools"])
        _phase(state, state_file, "management_started")


def _allowed_data_roots(install_root: Path) -> tuple[Path, ...]:
    configured = [Path(value) for value in os.environ.get("DC_ALLOWED_DATA_ROOTS", "").split(os.pathsep) if value]
    defaults = [install_root / "data", install_root.parent / "data", Path("/var/lib/domain-center"), Path("/var/lib/resolver-identity")]
    return tuple(path.absolute() for path in [*configured, *defaults])


def _data_path_allowed(path: Path, install_root: Path) -> bool:
    canonical = path.resolve(strict=False)
    if canonical in {Path("/"), Path("/var"), Path("/opt"), Path.home()}:
        return False
    return any(canonical == root.resolve(strict=False) or root.resolve(strict=False) in canonical.parents for root in _allowed_data_roots(install_root))


def _load_marker(data_dir: Path) -> dict[str, object]:
    marker = data_dir / DATA_MARKER
    if not marker.is_file() or marker.is_symlink():
        die("DATA002", "数据目录缺少安全所有权标记", "禁止认领或删除既有目录。")
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die("DATA002", f"数据所有权标记损坏：{exc}", "停止操作并核对安装状态。")
    if not isinstance(value, dict):
        die("DATA002", "数据所有权标记格式错误", "停止操作并核对安装状态。")
    return value


def _validate_marker(data_dir: Path, args: argparse.Namespace, state: dict[str, object]) -> dict[str, object]:
    marker = _load_marker(data_dir)
    expected = {
        "canonical_path": str(data_dir.resolve(strict=False)), "host": safe_host(args.expected_host), "role": args.role,
        "install_id": state.get("install_id"), "install_root": str(args.install_root.absolute()),
    }
    if any(marker.get(key) != value for key, value in expected.items()) or not _data_path_allowed(data_dir, args.install_root):
        die("DATA003", "数据标记与规范路径/主机/角色/安装 ID 不绑定", "拒绝破坏性操作；从可信状态备份恢复。")
    return marker


def _set_directory_owner(path: Path, uid: int | None, gid: int | None, mode: int) -> None:
    os.chmod(path, mode)
    if uid is None and gid is None:
        return
    if os.geteuid() != 0:
        _validate_directory_owner(path, uid, gid, "运行时目录")
        return
    os.chown(path, uid if uid is not None else path.stat().st_uid, gid if gid is not None else path.stat().st_gid)


def _validate_directory_owner(path: Path, uid: int | None, gid: int | None, label: str) -> None:
    if uid is not None and path.stat().st_uid != uid:
        die("DATA006", f"{label} UID 不符合配置：{path}", "使用批准的容器 UID/GID 创建运行时目录。")
    if gid is not None and path.stat().st_gid != gid:
        die("DATA006", f"{label} GID 不符合配置：{path}", "使用批准的容器 UID/GID 创建运行时目录。")


def _configured_id(env: dict[str, str], key: str) -> int | None:
    value = env.get(key, "").strip()
    if not value:
        return None
    if not value.isdigit() or int(value) <= 0:
        die("CFG006", f"{key} 必须是正整数", "使用固定的非特权 UID/GID。")
    return int(value)


def _ensure_owned_data(data_dir: Path, args: argparse.Namespace, state: dict[str, object], env: dict[str, str] | None = None) -> None:
    if not data_dir.is_absolute() or data_dir.is_symlink() or not _data_path_allowed(data_dir, args.install_root):
        die("CFG005", f"RI_FIELD_DATA_DIR 不在批准根目录：{data_dir}", "使用安装根 data、同级 data 或批准的 /var/lib 根目录。")
    owner_uid = _configured_id(env or {}, "RI_TRACE_PRODUCER_UID")
    owner_gid = _configured_id(env or {}, "RI_TRACE_PRODUCER_GID")
    resolver_uid = _configured_id(env or {}, "RI_KNOT_RESOLVER_UID")
    if owner_uid is not None and os.geteuid() != 0 and owner_uid != os.geteuid():
        die("DATA006", "当前用户无法创建批准 UID 所属的数据目录", "以 root 安装或使用与 producer UID 一致的安装用户。")
    data_existed = data_dir.exists()
    if data_existed:
        if not data_dir.is_dir():
            die("DATA001", "数据路径不是目录", "重新渲染配置。")
        _validate_marker(data_dir, args, state)
        if (data_dir.stat().st_mode & 0o7777) != 0o0750:
            die("DATA006", f"数据目录权限不符合 0750：{data_dir}", "按现场约定修复目录权限后重试。")
    else:
        data_dir.mkdir(parents=True, mode=0o750)
        marker = {
            "schema": "domain-center-data-owner-v1", "canonical_path": str(data_dir.resolve(strict=False)),
            "host": safe_host(args.expected_host), "role": args.role, "install_id": state["install_id"],
            "install_root": str(args.install_root.absolute()), "created_at": now(),
        }
        atomic_json(data_dir / DATA_MARKER, marker)
    _set_directory_owner(data_dir, owner_uid, owner_gid, 0o750)
    runtime_dirs = (data_dir / "knot-cache", data_dir / "trace") if args.role in {"r1", "r2", "r3"} else ()
    for runtime_dir in runtime_dirs:
        runtime_existed = runtime_dir.exists()
        if runtime_existed and (runtime_dir.is_symlink() or not runtime_dir.is_dir()):
            die("DATA005", f"运行时目录不安全：{runtime_dir}", "删除符号链接或非目录后重试。")
        if runtime_existed:
            expected_mode = 0o0750 if runtime_dir.name == "knot-cache" else 0o2770
            if (runtime_dir.stat().st_mode & 0o7777) != expected_mode:
                die("DATA006", f"运行时目录权限不符合 {expected_mode:04o}：{runtime_dir}", "按现场约定修复目录权限后重试。")
        else:
            runtime_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
        uid, gid, mode = ((resolver_uid, resolver_uid, 0o750)
                          if runtime_dir.name == "knot-cache"
                          else (owner_uid, owner_gid, 0o2770))
        _set_directory_owner(runtime_dir, uid, gid, mode)


def _read_state(root: Path) -> dict[str, object]:
    path = root / "state" / "install-state.json"
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        die("STATE002", "安装状态文件损坏", "保留现场并从最近备份恢复状态文件。")
    if not isinstance(value, dict):
        die("STATE002", "安装状态文件格式错误", "保留现场并从最近备份恢复状态文件。")
    return value


def _validate_state_identity(state: dict[str, object], args: argparse.Namespace) -> None:
    if state and (state.get("host") != safe_host(args.expected_host) or state.get("role") != args.role):
        die("STATE005", "安装状态属于其他主机或角色", "不得跨主机复制状态；使用正确安装根。")


def validate_active_install(args: argparse.Namespace) -> tuple[dict[str, object], Path]:
    if not host_matches(args.expected_host):
        die("HOST001", "当前主机与破坏性操作目标不一致", "在活动安装所属主机执行，禁止绕过。")
    state = _read_state(args.install_root)
    _validate_state_identity(state, args)
    expected_machine_id = state.get("machine_id")
    if expected_machine_id is not None and _machine_id() != expected_machine_id:
        die("HOST006", "当前主机 machine-id 与活动安装不一致", "在绑定的主机执行，禁止绕过。")
    current = args.install_root / "current"
    if not current.is_symlink():
        die("STATE006", "没有活动安装可操作", "核对安装根和当前发布指针。")
    target = current.resolve()
    try:
        marker = json.loads((target / ".installed.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die("STATE006", f"活动发布标记无效：{exc}", "停止破坏性操作并恢复状态。")
    if marker.get("host") != safe_host(args.expected_host) or marker.get("role") != args.role or marker.get("install_id") != state.get("install_id"):
        die("STATE006", "活动发布与主机/角色/安装 ID 不绑定", "停止破坏性操作并恢复可信状态。")
    return state, target


def _restore_previous_release(
    root: Path, target: Path, previous: Path | None, role: str, secret_dir: Path | None,
    state_file: Path,
) -> str | None:
    compose(target, ["down", "--remove-orphans"], check=False)
    if previous is None or not previous.is_dir():
        current = root / "current"
        if current.is_symlink():
            current.unlink()
        return None
    set_current(root, previous)
    previous_env = load_env(previous / "config" / ".env")
    recovery_state: dict[str, object] = {"phases": {}}
    start_ordered(previous, role, previous_env, secret_dir, recovery_state, state_file)
    return str(previous)


def install(args: argparse.Namespace, role_root: Path) -> None:
    evidence = preflight(args, role_root)
    root, state_file = args.install_root, args.install_root / "state" / "install-state.json"
    version = package_version(role_root)
    role_digest, config_digest = tree_hash(role_root), tree_hash(args.config_dir)
    images_digest = tree_hash(args.images) if args.images else "not-requested"
    metadata = _package_metadata(role_root)
    identity = {
        "schema": STATE_SCHEMA, "host": safe_host(args.expected_host), "role": args.role,
        "version": version, "role_sha256": role_digest, "config_sha256": config_digest,
        "images_sha256": images_digest, "source_commit": metadata.get("source_commit"),
        "manifest_sha256": metadata.get("release_manifest_sha256"),
    }
    if metadata.get("machine_id") is not None:
        identity["machine_id"] = metadata["machine_id"]
    with lock(root):
        state = _read_state(root)
        _validate_state_identity(state, args)
        same_input = state and all(state.get(key) == identity[key] for key in (
            "version", "role_sha256", "config_sha256", "images_sha256", "source_commit", "manifest_sha256",
        ))
        if state and not same_input:
            if not (args.no_start and state.get("status") == "complete" and (root / "current").is_symlink()):
                die("STATE007", "安装输入已改变：当前活动版本不能直接覆盖", "先使用 --no-start 暂存新版本，再执行 activate。")
            state = {**identity, "install_id": state["install_id"], "phases": {},
                     "active_release": state.get("active_release") or state.get("release"),
                     "staged_release": None}
        elif not state:
            state = {**identity, "install_id": str(uuid.uuid4()), "phases": {}}
        state.update({"status": "running", "status_zh": "执行中", "last_error": None})
        atomic_json(state_file, state)
        previous = (root / "current").resolve() if (root / "current").is_symlink() else None
        target: Path | None = None
        activation_attempted = False
        try:
            _phase(state, state_file, "validated", hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest())
            phases = state.get("phases", {})
            if args.images and not (isinstance(phases, dict) and "images_loaded" in phases):
                loader = role_root.parent / "common" / "load_images.py"
                run([sys.executable, str(loader), str(args.images)])
                _phase(state, state_file, "images_loaded", images_digest)
            elif not args.images:
                _phase(state, state_file, "images_not_requested", images_digest)
            env_values = load_env(args.config_dir / ".env")
            data_dir = Path(env_values.get("RI_FIELD_DATA_DIR", ""))
            _ensure_owned_data(data_dir, args, state, env_values)
            state["data_dir"] = str(data_dir.resolve(strict=False))
            target = root / "releases" / version
            if target.exists():
                installed = json.loads((target / ".installed.json").read_text(encoding="utf-8"))
                expected_marker = {"host": identity["host"], "role": args.role, "install_id": state["install_id"], "role_sha256": role_digest, "config_sha256": config_digest}
                if any(installed.get(key) != value for key, value in expected_marker.items()):
                    die("STATE003", f"发布目录标记与输入不匹配：{target}", "保留目录取证并使用新版本号。")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.parent / f".{version}.tmp-{os.getpid()}"
                if temporary.exists():
                    shutil.rmtree(temporary)
                copy_tree_secure(role_root, temporary)
                copy_tree_secure(args.config_dir, temporary / "config")
                atomic_json(temporary / ".installed.json", {
                    "host": identity["host"], "role": args.role, "version": version, "install_id": state["install_id"],
                    "role_sha256": role_digest, "config_sha256": config_digest, "installed_at": now(),
                })
                os.replace(temporary, target)
            _phase(state, state_file, "config_backed_up", config_digest)
            result = compose(target, ["config", "--quiet"], check=False)
            if result.returncode != 0:
                die("RUN001", f"Compose 静态检查失败：{redact_text(result.stdout or '')}", "修复配置后重试；程序指针已回滚，数据未删除。")
            previous = (root / "current").resolve() if (root / "current").is_symlink() else None
            if args.no_start:
                state.update({
                    "status": "staged", "status_zh": "已暂存（未启动）",
                    "release": str(previous) if previous else None,
                    "active_release": str(previous) if previous else None,
                    "staged_release": str(target), "activated": False,
                })
            else:
                activation_attempted = True
                start_ordered(target, args.role, env_values, args.secret_dir.absolute() if args.secret_dir else None, state, state_file)
                set_current(root, target)
                state.update({
                    "status": "complete", "status_zh": "完成", "release": str(target),
                    "active_release": str(target), "staged_release": None, "activated": True,
                })
            if previous and previous != target:
                atomic_text(root / "state" / "previous-release", f"{previous}\n")
            _phase(state, state_file, "evidence_written", hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest())
            atomic_json(state_file, state)
            print(f"安装完成：{args.role} {version}")
        except Exception as exc:
            recovery_error: Exception | None = None
            try:
                if activation_attempted and target is not None:
                    _restore_previous_release(
                        root, target, previous, args.role,
                        args.secret_dir.absolute() if args.secret_dir else None, state_file,
                    )
                elif previous and previous.is_dir():
                    set_current(root, previous)
                elif (root / "current").is_symlink() and (root / "current").resolve() != previous:
                    (root / "current").unlink(missing_ok=True)
            except Exception as recovery_exc:
                recovery_error = recovery_exc
            active = previous is not None and previous.is_dir() and recovery_error is None
            state.update({"status": "failed", "status_zh": "失败", "activated": active,
                          "release": str(previous) if active else None,
                          "active_release": str(previous) if active else None,
                          "staged_release": str(target) if target is not None else None,
                          "last_error": {
                "code": exc.code if isinstance(exc, LifecycleError) else "SYS001", "message": redact_text(str(exc)), "at": now(),
                "recovery_error": redact_text(str(recovery_error)) if recovery_error else None,
            }})
            atomic_json(state_file, state)
            raise


def activate(args: argparse.Namespace) -> None:
    if not host_matches(args.expected_host):
        die("HOST001", "当前主机与激活目标不一致", "在活动安装所属主机执行，禁止绕过。")
    root = args.install_root
    state_file = root / "state" / "install-state.json"
    state = _read_state(root)
    _validate_state_identity(state, args)
    expected_machine_id = state.get("machine_id")
    if expected_machine_id is not None and _machine_id() != expected_machine_id:
        die("HOST006", "当前主机 machine-id 与暂存安装不一致", "在绑定的主机执行，禁止绕过。")
    if state.get("status") != "staged" or not state.get("staged_release"):
        die("STATE008", "没有可激活的暂存发布", "先使用相同主机包执行 --no-start 暂存。")
    target = Path(str(state["staged_release"]))
    current = root / "current"
    previous = current.resolve() if current.is_symlink() else None
    if target.parent != (root / "releases").absolute() or not target.is_dir():
        die("STATE008", "暂存发布目录缺失或越界", "保留状态并重新生成可信主机包。")
    marker = json.loads((target / ".installed.json").read_text(encoding="utf-8"))
    if marker.get("install_id") != state.get("install_id") or marker.get("host") != state.get("host") or marker.get("role") != state.get("role"):
        die("STATE008", "暂存发布与安装状态不绑定", "拒绝激活不可信发布目录。")
    env = load_env(target / "config" / ".env")
    secret_dir = args.secret_dir.absolute() if args.secret_dir else None
    try:
        start_ordered(target, args.role, env, secret_dir, state, state_file)
        set_current(root, target)
    except Exception:
        if previous is not None:
            set_current(root, previous)
        raise
    if previous is not None and previous != target:
        atomic_text(root / "state" / "previous-release", f"{previous}\n")
    state.update({"status": "complete", "status_zh": "完成", "release": str(target),
                  "active_release": str(target), "staged_release": None, "activated": True,
                  "last_error": None})
    atomic_json(state_file, state)
    print(f"激活完成：{target}")


def status(args: argparse.Namespace) -> None:
    state_file = args.install_root / "state" / "install-state.json"
    if not state_file.is_file():
        die("STATE004", "尚无安装状态", "先执行 preflight 或 install。")
    print(state_file.read_text(encoding="utf-8"), end="")
    current = args.install_root / "current"
    if current.is_symlink() and (current / "docker-compose.yml").is_file() and shutil.which("docker"):
        result = compose(current.resolve(), ["ps"], check=False)
        if result.stdout:
            print(redact_text(result.stdout), end="")


def _sqlite_backup(source: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as source_db:
        with sqlite3.connect(destination) as backup_db:
            source_db.backup(backup_db)
            result = backup_db.execute("PRAGMA integrity_check").fetchone()
    integrity = str(result[0]) if result else "no-result"
    if integrity.lower() != "ok":
        destination.unlink(missing_ok=True)
        die("BACK001", f"SQLite 在线备份完整性检查失败：{integrity}", "保留现场并检查 evidence-v2.db 后重试。")
    os.chmod(destination, 0o600)
    return integrity


def backup(args: argparse.Namespace) -> None:
    state, target = validate_active_install(args)
    env = load_env(target / "config" / ".env")
    data = Path(env.get("RI_FIELD_DATA_DIR", ""))
    _validate_marker(data, args, state)
    output = args.output or Path.cwd() / "backup"
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    archive = output / f"{safe_host(args.expected_host)}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}.tar.gz"
    database = data / "evidence-v2.db"
    excluded = {"evidence-v2.db", "evidence-v2.db-wal", "evidence-v2.db-shm"}
    with tempfile.TemporaryDirectory(prefix=".domain-center-backup-", dir=output) as temp_name:
        staging = Path(temp_name)
        manifest: dict[str, object] = {
            "schema": "domain-center-backup-manifest-v1", "created_at": now(),
            "host": safe_host(args.expected_host), "role": args.role,
            "database": {"path": "data/evidence-v2.db", "status": "absent"},
            "excluded_live_files": sorted(excluded),
        }
        staged_database = staging / "evidence-v2.db"
        if args.role in {"r1", "r2", "r3"} and database.is_file() and not database.is_symlink():
            integrity = _sqlite_backup(database, staged_database)
            manifest["database"] = {
                "path": "data/evidence-v2.db", "status": "backed_up", "method": "sqlite3_online_backup",
                "integrity_check": integrity, "sha256": file_hash(staged_database),
            }
        atomic_json(staging / "backup-manifest.json", manifest, 0o600)
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as archive_file, tarfile.open(fileobj=archive_file, mode="w:gz") as tar:
            tar.add(data, arcname="data", recursive=False)
            for path in sorted(data.iterdir()):
                if path.name not in excluded:
                    tar.add(path, arcname=f"data/{path.name}", recursive=True)
            if staged_database.is_file():
                tar.add(staged_database, arcname="data/evidence-v2.db", recursive=False)
            tar.add(staging / "backup-manifest.json", arcname="backup-manifest.json", recursive=False)
    atomic_text(Path(f"{archive}.sha256"), f"{file_hash(archive)}  {archive.name}\n", 0o600)
    print(f"备份完成：{archive}")


def _redact_url(match: re.Match[str]) -> str:
    parsed = urlsplit(match.group(0))
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    query = urlencode([(key, "[REDACTED]" if SENSITIVE_QUERY_RE.search(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path, query, ""))


def redact_text(value: str) -> str:
    value = PEM_PRIVATE_RE.sub("[REDACTED PRIVATE KEY]", value)
    value = AUTH_RE.sub("Authorization: [REDACTED]", value)
    value = COOKIE_RE.sub(r"\1[REDACTED]", value)
    value = ASSIGNMENT_RE.sub(r"\1[REDACTED]", value)
    value = JWT_RE.sub("[REDACTED JWT]", value)
    return URL_RE.sub(_redact_url, value)


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
    allowed = {"install-state.json", "preflight.json", "previous-release"}
    for path in sorted(source.iterdir()):
        if path.name not in allowed or not path.is_file() or path.is_symlink() or SENSITIVE_NAME_RE.search(path.name):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        target = destination / path.name
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            target.write_text(redact_text(text), encoding="utf-8")
        else:
            target.write_text(json.dumps(redact_value(parsed), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        target.chmod(0o600)


def _known_secret_values(args: argparse.Namespace) -> set[str]:
    values: set[str] = set()
    state = _read_state(args.install_root)
    role = state.get("role")
    current = args.install_root / "current"
    if role not in ROLE_KIND or not current.is_symlink():
        return values
    try:
        env = load_env(current.resolve() / "config" / ".env")
    except LifecycleError:
        return values
    candidates: list[Path] = []
    for key in ("RI_MANAGEMENT_SECRET_DIR", "RI_NORN_CONFIG_DIR", "RI_NORN_TLS_DIR", "RI_RESOLVER_SECRET_DIR", "RI_AGENT_TLS_DIR", "RI_NORN_CLIENT_TLS_DIR"):
        path = Path(env.get(key, ""))
        if path.is_absolute() and path.is_dir() and not path.is_symlink():
            candidates.append(path)
    for root in candidates:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
                try:
                    secret = path.read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError):
                    continue
                if len(secret) >= 8:
                    values.add(secret)
    return values


def _scan_support(root: Path, known: set[str]) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if RESIDUAL_RE.search(text) or any(secret in text for secret in known):
            die("SUP001", f"支持包最终扫描发现残留秘密：{path.name}", "支持包未生成；修复脱敏规则后重试。")
        if URL_RE.search(text):
            for match in URL_RE.finditer(text):
                parsed = urlsplit(match.group(0))
                if parsed.username or parsed.password or any(SENSITIVE_QUERY_RE.search(key) and value != "[REDACTED]" for key, value in parse_qsl(parsed.query)):
                    die("SUP001", f"支持包发现凭据 URL：{path.name}", "支持包未生成；修复脱敏规则后重试。")


def support(args: argparse.Namespace) -> None:
    output = args.output or Path.cwd() / "support"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"support-{safe_host(args.expected_host)}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="domain-center-support-") as temp_name:
        temp = Path(temp_name)
        state = args.install_root / "state"
        if state.is_dir():
            _copy_redacted_state(state, temp / "state")
        atomic_text(temp / "system.txt", f"host={safe_host(socket.gethostname())}\nplatform={platform.platform()}\n", 0o600)
        current = args.install_root / "current"
        if current.is_symlink() and shutil.which("docker"):
            result = compose(current.resolve(), ["ps"], check=False)
            atomic_text(temp / "compose-ps.txt", redact_text(result.stdout or ""), 0o600)
        state_record = _read_state(args.install_root)
        manifest_files = [
            {"path": path.relative_to(temp).as_posix(), "sha256": file_hash(path)}
            for path in sorted(temp.rglob("*")) if path.is_file()
        ]
        atomic_json(temp / "manifest.json", {
            "schema_version": "domain-center-support-bundle-manifest-v1",
            "generated_at": now(),
            "host": safe_host(args.expected_host),
            "source_commit": state_record.get("source_commit"),
            "files": manifest_files,
            "real_server_deployed": False,
            "production_traffic_enabled": False,
        }, 0o600)
        _scan_support(temp, _known_secret_values(args))
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(temp, arcname="support")
    os.chmod(archive, 0o600)
    print(f"支持包完成（不含密钥与业务数据）：{archive}")


def _write_new_secret(path: Path, content: str) -> None:
    if path.exists():
        return
    atomic_text(path, content.rstrip("\n") + "\n", 0o600)


def prepare_secrets(args: argparse.Namespace) -> None:
    if not args.secret_dir:
        die("SEC200", "未指定密钥目录", "使用 --secret-dir 指向本机独立安全目录。")
    root = args.secret_dir.absolute()
    if args.secret_dir.is_symlink():
        die("SEC201", "密钥目录不能是符号链接", "使用本机真实目录并设置 0700 权限。")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    if args.role in {"r1", "r2", "r3"}:
        for name in ("secrets", "agent-tls", "norn-tls"):
            path = root / name
            if path.is_symlink():
                die("SEC201", f"密钥子目录不能是符号链接：{name}", "移除符号链接后重试。")
            path.mkdir(exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
        _write_new_secret(root / "secrets" / "agent_private_key", base64.b64encode(secrets.token_bytes(32)).decode())
        for name in ("trace_ingest_token", "agent_peer_token", "agent_wrapper_token"):
            _write_new_secret(root / "secrets" / name, secrets.token_urlsafe(32))
        agent_key = root / "agent-tls" / "agent.key"
        csr = root / "agent-tls" / "agent.csr"
        if not agent_key.exists() and shutil.which("openssl"):
            result = run(["openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-subj", f"/CN={safe_host(args.expected_host)}", "-keyout", str(agent_key), "-out", str(csr)], capture=True, check=False)
            if result.returncode != 0:
                agent_key.unlink(missing_ok=True)
                csr.unlink(missing_ok=True)
                die("SEC210", "Agent CSR 生成失败", "检查 openssl 后重试；未生成 CA 或证书。")
            os.chmod(agent_key, 0o600)
            os.chmod(csr, 0o600)
    elif args.role.startswith("norn-"):
        for name in ("node", "tls"):
            path = root / name
            path.mkdir(exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
    missing = [name for name in REQUIRED_SECRETS[args.role] if not (root / name).is_file()]
    if args.role in {"r1", "r2", "r3"}:
        for dirname, names in RESOLVER_TLS_FILES.items():
            required = names + (R1_TLS_FILES if args.role == "r1" and dirname == "agent-tls" else ())
            missing.extend(f"{dirname}/{name}" for name in required if not (root / dirname / name).is_file())
    evidence = {
        "host": safe_host(args.expected_host), "role": args.role, "checked_at": now(),
        "status": "blocked" if missing else "passed", "status_zh": "阻断" if missing else "通过",
        "missing": missing, "production_ca_generated": False,
    }
    atomic_json(args.install_root / "state" / "prepare-secrets.json", evidence)
    if missing:
        print("等待证书签发")
        print("仍需通过安全带外流程提供：" + "、".join(missing))
        return
    check_secret_tree(root, args.role)
    print("证书和密钥目录检查通过；未打印任何秘密，未生成生产 CA。")


def rollback(args: argparse.Namespace) -> None:
    state, current = validate_active_install(args)
    root = args.install_root
    with lock(root):
        previous_file = root / "state" / "previous-release"
        if not previous_file.is_file() or previous_file.is_symlink():
            die("ROLL001", "没有记录可回滚版本", "确认至少完成过两个不同版本的安装。")
        previous = Path(previous_file.read_text(encoding="utf-8").strip())
        if not previous.is_dir() or not (previous / ".installed.json").is_file() or previous.parent != (root / "releases").absolute():
            die("ROLL002", "回滚版本缺失、不完整或越界", "从可信备份恢复该发布目录。")
        marker = json.loads((previous / ".installed.json").read_text(encoding="utf-8"))
        if marker.get("host") != safe_host(args.expected_host) or marker.get("role") != args.role or marker.get("install_id") != state.get("install_id"):
            die("ROLL002", "回滚版本不属于当前安装", "禁止跨主机或跨角色回滚。")
        check = compose(previous, ["config", "--quiet"], check=False)
        if check.returncode != 0:
            die("ROLL003", "回滚目标配置检查失败", "当前程序指针未改变；修复回滚目标配置后重试。")
        try:
            env = load_env(previous / "config" / ".env")
            secret_dir: Path | None = None
            for key in ("RI_MANAGEMENT_SECRET_DIR", "RI_NORN_CONFIG_DIR", "RI_RESOLVER_SECRET_DIR"):
                configured = env.get(key)
                if configured:
                    candidate = Path(configured)
                    secret_dir = candidate.parent if key in {"RI_NORN_CONFIG_DIR", "RI_RESOLVER_SECRET_DIR"} else candidate
                    break
            start_ordered(previous, args.role, env, secret_dir, state, root / "state" / "install-state.json")
        except Exception:
            set_current(root, current)
            raise
        set_current(root, previous)
        atomic_text(previous_file, f"{current}\n")
        state.update({"release": str(previous), "active_release": str(previous), "staged_release": None,
                      "status": "complete", "status_zh": "完成", "activated": True, "last_error": None})
        atomic_json(root / "state" / "install-state.json", state)
        print(f"回滚完成：{previous}")


def uninstall(args: argparse.Namespace) -> None:
    state, target = validate_active_install(args)
    root = args.install_root
    with lock(root):
        env = load_env(target / "config" / ".env")
        data = Path(env.get("RI_FIELD_DATA_DIR", ""))
        if args.purge_data:
            _validate_marker(data, args, state)
            if str(data.resolve(strict=False)) != state.get("data_dir"):
                die("UN001", "数据目录与安装状态不一致", "拒绝清除；核对可信状态和所有权标记。")
        compose(target, ["down", "--remove-orphans"])
        (root / "current").unlink()
        if args.purge_data:
            shutil.rmtree(data)
        state.update({"status": "uninstalled", "status_zh": "已卸载", "activated": False, "data_purged": args.purge_data, "last_error": None})
        atomic_json(root / "state" / "install-state.json", state)
        print("卸载完成；密钥目录和历史发布未删除。" if not args.purge_data else "卸载完成；已清除本工具拥有且精确绑定的数据目录。")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="域名中心主机生命周期工具")
    value.add_argument("action", choices=("preflight", "prepare-secrets", "install", "activate", "status", "support", "backup", "rollback", "uninstall"))
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
        if args.action in {"install", "activate", "rollback", "uninstall"} and not args.yes:
            die("ARG001", "危险操作缺少 --yes", "确认变更窗口后显式传入 --yes。")
        if args.action == "preflight":
            preflight(args, role_root)
            print("预检通过。")
        elif args.action == "install":
            install(args, role_root)
        elif args.action == "activate":
            activate(args)
        elif args.action == "prepare-secrets":
            prepare_secrets(args)
        elif args.action == "status":
            status(args)
        elif args.action == "support":
            support(args)
        elif args.action == "backup":
            backup(args)
        elif args.action == "rollback":
            rollback(args)
        elif args.action == "uninstall":
            uninstall(args)
        return 0
    except LifecycleError as exc:
        print(f"错误代码：{exc.code}\n原因：{redact_text(exc.reason)}\n建议：{exc.advice}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ssl.SSLError) as exc:
        print(f"错误代码：SYS001\n原因：系统操作失败：{redact_text(str(exc))}\n建议：保留安装状态和支持包，修复系统后用相同命令续跑。", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"错误代码：SYS999\n原因：未预期错误：{redact_text(str(exc))}\n建议：停止变更并联系发布包维护人员。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
