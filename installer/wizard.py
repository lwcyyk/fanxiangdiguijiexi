#!/usr/bin/env python3
"""域名中心离线安装向导（仅使用 Python 标准库）。"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
from typing import NoReturn

ROLES = ("management", "norn-a", "norn-b", "r1", "r2", "r3")
ROLE_CN = {
    "management": "管理节点",
    "norn-a": "Norn A 节点",
    "norn-b": "Norn B 节点",
    "r1": "R1 首跳解析节点",
    "r2": "R2 上游解析节点",
    "r3": "R3 上游解析节点",
}
ERRORS = {
    "E001": ("参数不完整或格式错误", "使用 --help 查看参数，并按站点清单填写。"),
    "E002": ("当前主机与安装包指定主机不一致", "将安装包复制到指定主机；禁止绕过主机校验。"),
    "E003": ("预检未通过", "按输出修复环境后重新执行；已完成步骤会安全续跑。"),
    "E004": ("安装执行失败", "查看 support 采集包和安装状态，修复后重新执行同一命令。"),
    "E005": ("安装包内容不可信或不完整", "重新从受信介质复制并核对发布校验值。"),
    "E006": ("密钥材料不符合约束", "使用独立安全介质提供所需文件，勿在命令行传入密钥。"),
    "E007": ("不支持的操作", "使用 --help 中列出的操作。"),
    "E008": ("需要交互输入但当前为非交互模式", "提供 --role、--expected-host 和 --yes，或在终端中运行。"),
}


class InstallError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def fail(code: str, detail: str = "") -> NoReturn:
    reason, advice = ERRORS.get(code, ("未知错误", "联系发布包维护人员。"))
    if detail:
        reason = f"{reason}：{detail}"
    print(f"错误代码：{code}\n原因：{reason}\n建议：{advice}", file=sys.stderr)
    raise SystemExit(2)


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    printable = " ".join(shlex.quote(item) for item in command)
    print(f"执行：{printable}")
    try:
        subprocess.run(command, check=True, env=env)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InstallError("E004", str(exc)) from exc


def safe_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", value):
        raise InstallError("E001", f"主机名不合法：{value!r}")
    return value


def local_host_names() -> set[str]:
    names: set[str] = set()
    for value in (socket.gethostname(), socket.getfqdn(), os.environ.get("HOSTNAME", "")):
        if value:
            normalized = value.strip().lower().rstrip(".")
            names.add(normalized)
            names.add(normalized.split(".", 1)[0])
    return names


def check_expected_host(expected: str, override_actual: str | None = None) -> None:
    expected = safe_host(expected)
    names = local_host_names()
    if override_actual:
        actual = safe_host(override_actual)
        names = {actual, actual.split(".", 1)[0]}
    if expected not in names and expected.split(".", 1)[0] not in names:
        raise InstallError("E002", f"期望 {expected}，实际 {', '.join(sorted(names))}")


def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{label}{suffix}：").strip()
    return answer or default


def load_package_metadata(root: Path) -> dict[str, object]:
    candidates = (root / "expected-host.json", root / "package.json", root / "manifest.json", root / "EXPECTED-HOST.json")
    for path in candidates:
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise InstallError("E005", f"无法读取 {path.name}：{exc}") from exc
            if not isinstance(value, dict):
                raise InstallError("E005", f"{path.name} 顶层必须是对象")
            return value
    return {}


def infer_package_root(script: Path) -> Path:
    candidate = script.resolve().parent.parent / "deploy" / "easy-install" / "product-kit"
    return candidate if candidate.is_dir() else script.resolve().parent


def select_role(args: argparse.Namespace, metadata: dict[str, object]) -> str:
    role = args.role or metadata.get("role")
    if role:
        if role not in ROLES:
            raise InstallError("E001", f"角色不合法：{role}")
        return str(role)
    if not sys.stdin.isatty():
        raise InstallError("E008", "缺少 --role")
    print("请选择本机角色：")
    for number, name in enumerate(ROLES, 1):
        print(f"  {number}. {ROLE_CN[name]}")
    value = prompt("序号")
    try:
        return ROLES[int(value) - 1]
    except (ValueError, IndexError) as exc:
        raise InstallError("E001", "角色序号无效") from exc


def validate_secret_dir(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise InstallError("E006", "密钥目录必须是已存在的绝对路径且不能是符号链接")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise InstallError("E006", f"密钥目录权限必须不宽于 0700，当前为 {mode:04o}")
    for child in path.iterdir():
        if child.is_symlink():
            raise InstallError("E006", f"密钥文件不能是符号链接：{child.name}")
        if child.is_file() and child.stat().st_mode & 0o077:
            raise InstallError("E006", f"密钥文件权限必须不宽于 0600：{child.name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="域名中心离线安装向导（中文、无颜色）")
    parser.add_argument("action", nargs="?", default="install", choices=(
        "install", "preflight", "status", "support", "backup", "rollback", "uninstall"
    ))
    parser.add_argument("--role", choices=ROLES, help="本机角色")
    parser.add_argument("--expected-host", help="安装包指定的主机名")
    parser.add_argument("--actual-host", help=argparse.SUPPRESS)
    parser.add_argument("--no-start", action="store_true", help="安装但不启动服务")
    parser.add_argument("--package-root", type=Path, help="product-kit 根目录")
    parser.add_argument("--config-dir", type=Path, help="本机渲染配置目录")
    parser.add_argument("--secret-dir", type=Path, help="已准备的受限密钥目录")
    parser.add_argument("--install-root", type=Path, default=Path("/opt/domain-center"))
    parser.add_argument("--images", type=Path, help="离线镜像目录")
    parser.add_argument("--output", type=Path, help="支持包或备份输出目录")
    parser.add_argument("--yes", action="store_true", help="非交互确认")
    parser.add_argument("--purge-data", action="store_true", help="卸载时删除本工具拥有的数据")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        package_root = (args.package_root or infer_package_root(Path(__file__))).resolve()
        metadata_root = package_root.parent if package_root.name == "product-kit" else package_root
        metadata = load_package_metadata(metadata_root)
        role = select_role(args, metadata)
        expected = args.expected_host or metadata.get("expected_host") or metadata.get("hostname")
        if not expected:
            if not sys.stdin.isatty():
                raise InstallError("E008", "缺少 --expected-host")
            expected = prompt("本安装包指定主机名")
        check_expected_host(str(expected), args.actual_host)

        role_root = package_root / role
        control = role_root / "安装工具"
        if not control.is_file():
            raise InstallError("E005", f"角色工具不存在：{control}")
        command = [str(control), args.action, "--expected-host", str(expected),
                   "--install-root", str(args.install_root)]
        if args.config_dir:
            command += ["--config-dir", str(args.config_dir.resolve())]
        if args.secret_dir:
            validate_secret_dir(args.secret_dir.resolve())
            command += ["--secret-dir", str(args.secret_dir.resolve())]
        if args.images:
            command += ["--images", str(args.images.resolve())]
        if args.output:
            command += ["--output", str(args.output.resolve())]
        if args.purge_data:
            command.append("--purge-data")
        if args.no_start:
            command.append("--no-start")
        if args.yes:
            command.append("--yes")
        elif args.action in {"install", "rollback", "uninstall"}:
            if not sys.stdin.isatty():
                raise InstallError("E008", "危险操作需要 --yes")
            if prompt(f"确认在 {expected} 执行{args.action}？输入“是”继续") != "是":
                print("已取消。")
                return 0
        run(command)
        print(f"完成：{ROLE_CN[role]} {args.action}")
        return 0
    except InstallError as exc:
        fail(exc.code, exc.detail)
    except KeyboardInterrupt:
        fail("E001", "操作被中断")
    except Exception as exc:  # ensure every externally visible error follows the contract
        fail("E004", str(exc))


if __name__ == "__main__":
    sys.exit(main())
