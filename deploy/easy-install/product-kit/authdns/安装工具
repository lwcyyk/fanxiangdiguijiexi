#!/usr/bin/env python3
"""角色入口：从目录名锁定角色，防止跨角色误装。"""

from __future__ import annotations

import os
from pathlib import Path
import sys


def main() -> int:
    role = Path(__file__).resolve().parent.name
    core = Path(__file__).resolve().parent.parent / "common" / "lifecycle.py"
    actions = {
        "安装": "install", "预检": "preflight", "准备证书和密钥": "prepare-secrets", "查看状态": "status",
        "收集支持包": "support", "备份": "backup", "回滚": "rollback", "卸载": "uninstall",
    }
    supplied = sys.argv[1:]
    implied = actions.get(Path(__file__).name)
    if implied:
        supplied = [implied, *supplied]
    command = [sys.executable, str(core), *supplied, "--role", role]
    try:
        os.execv(sys.executable, command)
    except OSError as exc:
        print(f"错误代码：BOOT001\n原因：无法启动生命周期核心：{exc}\n建议：确认产品包完整且 Python 3 可用。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
