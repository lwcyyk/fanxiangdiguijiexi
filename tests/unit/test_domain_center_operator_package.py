from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys


REPO = Path(__file__).resolve().parents[2]
BUILDER_PATH = REPO / "tools" / "build_domain_center_operator_package.py"
OPERATOR_PATH = REPO / "tools" / "domain_center_operator.py"
PRIVATE_BUILDER_PATH = REPO / "tools" / "build_domain_center_private_bundle.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = load("domain_center_operator_builder", BUILDER_PATH)
operator = load("domain_center_operator", OPERATOR_PATH)
private_builder = load("domain_center_private_builder", PRIVATE_BUILDER_PATH)


def build_without_images(tmp_path: Path) -> Path:
    missing = {key: tmp_path / f"missing-{key}.tar" for key in builder.IMAGE_SPECS}
    output = tmp_path / "resolver-identity-domain-center"
    manifest = builder.build(output, missing)
    assert set(manifest["missing_oci_archives"]) == set(builder.IMAGE_SPECS)
    return output


def test_public_package_has_all_seven_numbered_roles_and_metadata(tmp_path: Path):
    output = build_without_images(tmp_path)
    expected = {directory: role for directory, role, _ in builder.ROLES}
    assert list(expected) == [
        "01-management", "02-norn-a", "03-norn-b", "04-authdns", "05-r3", "06-r2", "07-r1"
    ]
    for directory, role in expected.items():
        root = output / directory
        assert root.is_dir()
        for name in ("install.sh", "check.sh", "diagnose.sh", "README.md"):
            assert (root / name).is_file()
        assert f"--role {role}" in (root / "install.sh").read_text(encoding="utf-8")
    for name in ("README.md", "VERSION", "MANIFEST.json", "SHA256SUMS", "check-all.sh"):
        assert (output / name).is_file()
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert [item["role"] for item in manifest["roles"]] == list(operator.ROLES)
    assert manifest["contains_secrets"] is False
    assert manifest["contains_database"] is False
    assert manifest["contains_runtime_state"] is False


def test_public_package_excludes_secret_database_and_runtime_state(tmp_path: Path):
    output = build_without_images(tmp_path)
    forbidden_name = re.compile(r"(?:\.env|\.db|\.sqlite|\.wal|\.shm|private[_-]?key|secret|token|password)", re.I)
    payload = bytearray()
    for path in output.rglob("*"):
        if path.is_file():
            assert not forbidden_name.search(path.name)
            payload.extend(path.read_bytes())
    assert b"BEGIN PRIVATE KEY" not in payload
    assert b"down -v" not in payload


def test_install_and_check_command_shape_is_fixed_offline_and_idempotent(tmp_path: Path):
    output = build_without_images(tmp_path)
    operator_text = (output / "common" / "domain_center_operator.py").read_text(encoding="utf-8")
    loader_text = (output / "common" / "load_images.py").read_text(encoding="utf-8")
    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "sudo ./install.sh" in readme
    assert "sudo ./check.sh" in readme
    assert '"up", "-d", "--pull", "never", "--remove-orphans"' in operator_text
    assert '"docker", "load", "--input"' in loader_text
    assert '["docker", "pull"' not in operator_text
    assert '["docker", "pull"' not in loader_text
    assert "--private-bundle" not in (output / "01-management" / "install.sh").read_text(encoding="utf-8")
    assert "IMG001" in operator_text


def test_redaction_covers_private_keys_tokens_and_credential_urls():
    value = (
        "Authorization: Bearer top-secret\n"
        "Cookie: sid=abc\n"
        "password=hunter2-value\n"
        "https://user:pass@example.invalid/path?token=visible\n"
        "-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----\n"
    )
    redacted = operator.redact(value)
    for secret in ("top-secret", "sid=abc", "hunter2-value", "user:pass", "token=visible", "material"):
        assert secret not in redacted
    assert "[REDACTED" in redacted


def test_private_bundle_builder_emits_host_project_and_hash_bound_manifest(tmp_path: Path):
    compose = tmp_path / "compose.yml"
    environment = tmp_path / "node.env"
    secrets = tmp_path / "source-secrets"
    compose.write_text("services: {}\n", encoding="utf-8")
    environment.write_text("RI_IMAGE=offline/example:ri-0123456789abcdef\n", encoding="utf-8")
    secrets.mkdir()
    (secrets / "token").write_text("private-test-token\n", encoding="utf-8")
    output = private_builder.build(
        tmp_path / "bundle",
        "r1",
        "ri-r1",
        "ri-r1",
        compose,
        environment,
        secrets,
    )
    manifest = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == operator.BUNDLE_SCHEMA
    assert manifest["role"] == "r1"
    assert manifest["expected_host"] == "ri-r1"
    assert manifest["compose_project"] == "ri-r1"
    assert manifest["compose"]["sha256"] == operator.sha256(output / "compose.yml")
    assert manifest["environment"]["sha256"] == operator.sha256(output / "node.env")
    assert (output.stat().st_mode & 0o777) == 0o700
    assert ((output / "secrets" / "token").stat().st_mode & 0o777) == 0o600
    assert (output / "kresd.conf").is_file()


def test_missing_oci_archives_are_reported_not_fabricated(tmp_path: Path):
    output = build_without_images(tmp_path)
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert set(manifest["missing_oci_archives"]) == set(builder.IMAGE_SPECS)
    for directory, _, _ in builder.ROLES:
        assert not (output / directory / "images" / "image-lock.json").exists()
        assert not list((output / directory).rglob("*.tar"))
