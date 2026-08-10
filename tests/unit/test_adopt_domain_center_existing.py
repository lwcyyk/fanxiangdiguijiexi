from __future__ import annotations

import importlib.util
from pathlib import Path
import sqlite3
import sys

import pytest


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "adopt_domain_center_existing.py"


def load():
    spec = importlib.util.spec_from_file_location("adopt_domain_center_existing", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adopt = load()


def test_quick_check_is_read_only_and_accepts_valid_databases(tmp_path: Path):
    for name in adopt.DB_NAMES:
        with sqlite3.connect(tmp_path / name) as database:
            database.execute("CREATE TABLE sample(value TEXT)")
            database.execute("INSERT INTO sample VALUES ('preserved')")
    assert adopt.quick_check(tmp_path) == {name: "ok" for name in adopt.DB_NAMES}
    for name in adopt.DB_NAMES:
        with sqlite3.connect(tmp_path / name) as database:
            assert database.execute("SELECT value FROM sample").fetchone() == ("preserved",)


def test_adopt_command_never_contains_destructive_volume_operations():
    text = TOOL.read_text(encoding="utf-8")
    assert '"up", "-d", "--pull", "never", "--no-deps"' in text
    assert "down -v" not in text
    assert '"down"' not in text
    assert '"volume", "rm"' not in text


def test_invalid_project_is_rejected_before_docker(tmp_path: Path):
    args = type("Args", (), {
        "role": "r1",
        "project": "bad project;rm",
        "compose": tmp_path / "compose.yml",
        "environment": tmp_path / "node.env",
        "data_dir": tmp_path,
        "output": tmp_path / "evidence.json",
    })()
    with pytest.raises(adopt.AdoptError, match="invalid"):
        adopt.adopt(args)
