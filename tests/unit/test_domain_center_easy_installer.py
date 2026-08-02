from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from types import ModuleType, SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "tools" / "build_domain_center_site_bundle.py"
WIZARD_PATH = REPO_ROOT / "installer" / "wizard.py"
LIFECYCLE_PATH = (
    REPO_ROOT / "deploy" / "easy-install" / "product-kit" / "common" / "lifecycle.py"
)
IMAGE_LOADER_PATH = (
    REPO_ROOT / "deploy" / "easy-install" / "product-kit" / "common" / "load_images.py"
)


def _load_module(name: str, path: Path) -> ModuleType:
    """Import executable tools without requiring their directories to be packages."""
    if not path.is_file():
        pytest.fail(f"required easy-installer module is missing: {path}", pytrace=False)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


generator = _load_module("build_domain_center_site_bundle", GENERATOR_PATH)
wizard = _load_module("domain_center_installer_wizard", WIZARD_PATH)
lifecycle = _load_module("domain_center_product_lifecycle", LIFECYCLE_PATH)
image_loader = _load_module("domain_center_product_load_images", IMAGE_LOADER_PATH)


def _digest(index: int) -> str:
    return f"sha256:{index:064x}"


def _base_inventory() -> dict:
    """Small real-mode inventory exercising R1/R2/R3 role boundaries."""
    return {
        "schema_version": "domain-center-easy-installer/v1",
        "site": {"id": "dc-test", "name_zh": "域名中心离线测试站点"},
        "release": {
            "version": "0.3.0-test",
            "git_commit": "a" * 40,
            "images": {
                "management": f"registry.internal/management@{_digest(1)}",
                "norn": f"registry.internal/norn@{_digest(2)}",
                "nginx": f"registry.internal/nginx@{_digest(3)}",
                "resolver": f"registry.internal/resolver@{_digest(4)}",
                "knot": f"registry.internal/knot@{_digest(5)}",
            },
        },
        "hosts": [
            {"id": "dc-mgmt-01", "hostname": "dc-mgmt-01", "role": "management"},
            {"id": "dc-norn-a", "hostname": "dc-norn-a", "role": "norn-a"},
            {"id": "dc-norn-b", "hostname": "dc-norn-b", "role": "norn-b"},
            {
                "id": "dc-r1-01",
                "hostname": "dc-r1-01",
                "role": "r1",
                "resolver_role": "first-hop",
                "shadow_port": 1053,
            },
            {
                "id": "dc-r2-01",
                "hostname": "dc-r2-01",
                "role": "r2",
                "resolver_role": "upstream",
            },
            {
                "id": "dc-r3-01",
                "hostname": "dc-r3-01",
                "role": "r3",
                "resolver_role": "upstream",
            },
        ],
        "external_requirements": {
            "resolver_trace": {"status": "blocked", "status_zh": "阻断"},
            "production_cutover": {"status": "not_run", "status_zh": "未运行"},
        },
    }


def _call_validate_inventory(inventory: dict) -> None:
    validate = getattr(generator, "validate_inventory", None)
    assert callable(validate), "generator must expose validate_inventory(inventory)"
    validate(inventory)


def _render_bundle(inventory: dict, destination: Path) -> Path:
    """Accept the two intentional public spellings while agents converge."""
    render = getattr(generator, "build_site_bundle", None) or getattr(generator, "render", None)
    assert callable(render), "generator must expose build_site_bundle(...) or render(...)"
    try:
        result = render(inventory, destination)
    except TypeError:
        inventory_path = destination.parent / "site-inventory.json"
        inventory_path.write_text(
            json.dumps(inventory, ensure_ascii=False), encoding="utf-8"
        )
        result = render(inventory_path, destination)
    return Path(result) if result is not None else destination


def _error_type() -> type[Exception]:
    return getattr(generator, "BundleError", getattr(generator, "DeliveryError", ValueError))


def _tree_names(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix().lower()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def _archive_bytes(files: dict[str, bytes]) -> bytes:
    """Create a deterministic fixture archive without invoking the network."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name in sorted(files):
                info = tarfile.TarInfo(name)
                info.size = len(files[name])
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(files[name]))
    return output.getvalue()


@pytest.mark.parametrize(
    "field, duplicate",
    [
        ("id", "dc-r1-01"),
        ("hostname", "dc-r1-01"),
    ],
)
def test_inventory_rejects_duplicate_host_keys(field: str, duplicate: str):
    inventory = _base_inventory()
    inventory["hosts"][-1][field] = duplicate

    with pytest.raises(_error_type(), match="(?i)duplicate|重复|unique|唯一"):
        _call_validate_inventory(inventory)


@pytest.mark.parametrize(
    "role, resolver_role",
    [
        ("r1", "upstream"),
        ("r2", "first-hop"),
        ("r3", "first-hop"),
        ("wrapper", "first-hop"),
    ],
)
def test_inventory_rejects_unknown_or_inconsistent_roles(role: str, resolver_role: str):
    inventory = _base_inventory()
    inventory["hosts"][-1].update(role=role, resolver_role=resolver_role)

    with pytest.raises(_error_type(), match="(?i)role|角色|first-hop|upstream"):
        _call_validate_inventory(inventory)


@pytest.mark.parametrize(
    "reference",
    [
        "registry.internal/resolver:latest",
        "registry.internal/resolver:0.3.0",
        "registry.internal/resolver@sha256:abcd",
        f"registry.internal/resolver:latest@{_digest(4)}",
        f"https://user:password@registry.internal/resolver@{_digest(4)}",
    ],
)
def test_oci_reference_rejects_movable_short_or_credentialed_values(reference: str):
    with pytest.raises(Exception, match="(?i)sha256|digest|摘要|凭据|固定"):
        image_loader.digest_from_reference(reference)


def test_offline_image_manifest_rejects_path_traversal(tmp_path: Path):
    manifest = tmp_path / "image-archives.json"
    manifest.write_text(
        json.dumps(
            {
                "archives": [
                    {
                        "filename": "../outside.tar",
                        "sha256": "b" * 64,
                        "image": f"registry.internal/resolver@{_digest(4)}",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(image_loader.ImageError, match="安全|文件名"):
        image_loader.parse_manifest(manifest)


def test_offline_image_load_uses_fake_docker_and_verifies_repo_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    archive = tmp_path / "resolver.tar"
    archive.write_bytes(b"offline image bytes")
    reference = f"registry.internal/resolver@{_digest(4)}"
    (tmp_path / "image-archives.json").write_text(
        json.dumps(
            {
                "archives": [
                    {
                        "filename": archive.name,
                        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                        "image": reference,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([reference]), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(image_loader.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])

    assert image_loader.main() == 0
    assert ["docker", "version"] in calls
    assert ["docker", "load", "--input", str(archive)] in calls
    assert any(command[:3] == ["docker", "image", "inspect"] for command in calls)
    assert not any("pull" in command for command in calls)


def test_site_archive_is_byte_for_byte_deterministic(tmp_path: Path):
    first = _render_bundle(_base_inventory(), tmp_path / "first")
    second = _render_bundle(copy.deepcopy(_base_inventory()), tmp_path / "second")
    first_archives = sorted(first.glob("*.tar.gz"))
    second_archives = sorted(second.glob("*.tar.gz"))

    assert first_archives, "site bundle must contain at least one .tar.gz archive"
    assert [path.name for path in first_archives] == [path.name for path in second_archives]
    assert [path.read_bytes() for path in first_archives] == [
        path.read_bytes() for path in second_archives
    ]
    for archive in first_archives:
        with gzip.open(archive, "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:") as tar:
                members = tar.getmembers()
        assert [member.name for member in members] == sorted(member.name for member in members)
        assert {member.mtime for member in members} <= {0}
        assert {member.uid for member in members} <= {0}
        assert {member.gid for member in members} <= {0}


def test_wizard_rejects_expected_host_mismatch_before_running_product_tool(
    monkeypatch: pytest.MonkeyPatch,
):
    invoked = False

    def forbidden_run(*args: object, **kwargs: object) -> None:
        nonlocal invoked
        invoked = True

    monkeypatch.setattr(wizard, "run", forbidden_run)
    with pytest.raises(wizard.InstallError) as raised:
        wizard.check_expected_host("dc-r1-01.example", "dc-r2-01.example")

    assert raised.value.code == "E002"
    assert invoked is False


def test_lifecycle_install_resumes_and_is_idempotent_with_fake_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    role_root = tmp_path / "product-kit" / "r1"
    role_root.mkdir(parents=True)
    (role_root / "PACKAGE-VERSION").write_text("0.3.0-test\n", encoding="utf-8")
    (role_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(
        "RI_FIELD_COMPOSE_PROJECT=dc-test-r1\n", encoding="utf-8"
    )
    install_root = tmp_path / "install"
    probes: list[str] = []

    monkeypatch.setattr(
        lifecycle,
        "preflight",
        lambda args, root: probes.append("preflight")
        or {"result": "passed", "status_zh": "通过"},
    )
    monkeypatch.setattr(
        lifecycle,
        "compose",
        lambda target, action, check=True: probes.append("compose:" + " ".join(action))
        or subprocess.CompletedProcess(action, 0, "", ""),
    )
    args = SimpleNamespace(
        install_root=install_root,
        expected_host="dc-r1-01",
        role="r1",
        images=None,
        config_dir=config,
        secret_dir=tmp_path / "secrets",
        no_start=False,
    )

    lifecycle.install(args, role_root)
    first_target = (install_root / "current").resolve()
    lifecycle.install(args, role_root)

    state = json.loads((install_root / "state" / "install-state.json").read_text())
    assert state["status"] == "complete"
    assert state["preflight"] == "complete"
    assert state["images"] == "not-requested"
    assert (install_root / "current").resolve() == first_target
    assert len(list((install_root / "releases").iterdir())) == 1
    assert probes.count("compose:up -d") == 2


def test_support_bundle_redacts_secrets_and_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    install_root = tmp_path / "install"
    state = install_root / "state"
    state.mkdir(parents=True)
    (state / "install-state.json").write_text(
        json.dumps(
            {
                "status": "failed",
                "authorization": "Bearer top-secret-token",
                "rpc_url": "https://user:password@rpc.invalid/api?key=secret",
                "message_zh": "预检失败",
            }
        ),
        encoding="utf-8",
    )
    (state / "agent_private.key").write_text("PRIVATE-KEY-MATERIAL", encoding="utf-8")
    (state / "wrapper-token.txt").write_text("WRAPPER-TOKEN", encoding="utf-8")
    output = tmp_path / "support"
    monkeypatch.setattr(lifecycle.shutil, "which", lambda command: None)
    args = SimpleNamespace(
        output=output,
        expected_host="dc-r1-01",
        install_root=install_root,
    )

    lifecycle.support(args)
    archive = next(output.glob("support-*.tar.gz"))
    with tarfile.open(archive, "r:gz") as handle:
        names = handle.getnames()
        payload_parts: list[bytes] = []
        for member in handle.getmembers():
            if not member.isfile():
                continue
            stream = handle.extractfile(member)
            if stream is not None:
                payload_parts.append(stream.read())
        payload = b"\n".join(payload_parts)

    assert not any("key" in name.lower() or "token" in name.lower() for name in names)
    for secret in (
        b"PRIVATE-KEY-MATERIAL",
        b"WRAPPER-TOKEN",
        b"top-secret-token",
        b"user:password",
        b"key=secret",
    ):
        assert secret not in payload
    assert "预检失败".encode() in payload


def test_r2_r3_packages_have_no_wrapper_structure(tmp_path: Path):
    bundle = _render_bundle(_base_inventory(), tmp_path / "bundle")
    archives = sorted(bundle.glob("*.tar.gz"))
    assert archives

    inspected = set()
    for archive in archives:
        with tarfile.open(archive, "r:gz") as handle:
            names = {member.name.lower() for member in handle.getmembers()}
            payload_parts: list[bytes] = []
            for member in handle.getmembers():
                if not member.isfile() or member.size > 2_000_000:
                    continue
                stream = handle.extractfile(member)
                if stream is not None:
                    payload_parts.append(stream.read())
            metadata = b"\n".join(payload_parts).lower()
        role = "r2" if b'"role": "r2"' in metadata or b"role=r2" in metadata else None
        role = "r3" if b'"role": "r3"' in metadata or b"role=r3" in metadata else role
        if role:
            inspected.add(role)
            assert not any("wrapper" in name for name in names)
            assert b"wrapper:" not in metadata
            assert b"profiles: [first-hop]" not in metadata
            assert b"1053:1053" not in metadata

    assert inspected == {"r2", "r3"}, "bundle must contain identifiable R2 and R3 packages"


def test_r1_package_encodes_shadow_udp_and_tcp_1053(tmp_path: Path):
    bundle = _render_bundle(_base_inventory(), tmp_path / "bundle")
    r1_payload = b""
    for archive in bundle.glob("*.tar.gz"):
        with tarfile.open(archive, "r:gz") as handle:
            payload_parts: list[bytes] = []
            for member in handle.getmembers():
                if not member.isfile() or member.size > 2_000_000:
                    continue
                stream = handle.extractfile(member)
                if stream is not None:
                    payload_parts.append(stream.read())
            payload = b"\n".join(payload_parts)
        lowered = payload.lower()
        if b'"role": "r1"' in lowered or b"role=r1" in lowered:
            r1_payload += payload

    text = r1_payload.decode("utf-8", errors="replace").lower()
    assert "wrapper" in text
    assert "1053" in text
    assert "1053/udp" in text or "udp" in text
    assert "1053/tcp" in text or "tcp" in text
    assert "53:1053" not in text, "Shadow must not bind the production host port 53"


def test_evidence_preserves_blocked_not_run_and_chinese_entries(tmp_path: Path):
    bundle = _render_bundle(_base_inventory(), tmp_path / "bundle")
    json_documents: list[dict] = []
    for path in bundle.rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            json_documents.append(value)
    for archive in bundle.glob("*.tar.gz"):
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle.getmembers():
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                stream = handle.extractfile(member)
                if stream is None:
                    continue
                try:
                    value = json.loads(stream.read().decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict):
                    json_documents.append(value)

    serialized = json.dumps(json_documents, ensure_ascii=False, sort_keys=True)
    assert '"blocked"' in serialized
    assert '"not_run"' in serialized
    assert "阻断" in serialized
    assert "未运行" in serialized
    assert "域名中心" in serialized


def test_documentation_contains_required_chinese_operator_guidance():
    docs = [
        REPO_ROOT / "docs" / "easy-install" / "一页纸安装卡.md",
        REPO_ROOT / "docs" / "easy-install" / "域名中心图文安装手册.md",
        REPO_ROOT / "docs" / "easy-install" / "技术运维手册.md",
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert len(text) >= 500
        assert "阻断" in text
        assert "安全" in text or "秘密" in text
    combined = "\n".join(path.read_text(encoding="utf-8") for path in docs)
    for required in (
        "R1",
        "R2/R3",
        "Wrapper",
        "1053",
        "expected_host",
        "blocked",
        "not_run",
        "脱敏",
        "外部",
        "离线",
    ):
        assert required in combined
