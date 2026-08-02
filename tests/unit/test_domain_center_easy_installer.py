from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
from types import ModuleType, SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "tools" / "build_domain_center_site_bundle.py"
PRODUCT_KIT = REPO_ROOT / "deploy" / "easy-install" / "product-kit"
WIZARD_PATH = REPO_ROOT / "installer" / "wizard.py"
LIFECYCLE_PATH = PRODUCT_KIT / "common" / "lifecycle.py"
IMAGE_LOADER_PATH = PRODUCT_KIT / "common" / "load_images.py"


def _load_module(name: str, path: Path) -> ModuleType:
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


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    images: dict[str, dict[str, str]] = {}
    release_images: dict[str, str] = {}
    for key in sorted(generator.EXPECTED_IMAGE_KEYS):
        archive = tmp_path / f"{key}.oci.tar"
        digest: dict[str, str] = {}
        repository = f"registry.internal/domain-center/{key}"
        generator._make_test_oci(archive, digest, repository)
        digests[key] = digest["digest"]
        images[key] = {"archive": archive.name, "repository": repository}
        release_images[key] = f"source.invalid/domain-center/{key}@sha256:{digest['digest']}"
    release = {"version": "0.3.0-test", "git_commit": "a" * 40, "images": release_images}
    release_path = tmp_path / "release-manifest.json"
    _write_json(release_path, release)
    site = {
        "schema_version": generator.SCHEMA,
        "release": {
            "version": release["version"],
            "source_commit": release["git_commit"],
            "manifest_sha256": hashlib.sha256(release_path.read_bytes()).hexdigest(),
        },
        "platform": {"os": "linux", "architecture": "amd64"},
        "hosts": [
            {"hostname": "dc-mgmt-01", "role": "management"},
            {"hostname": "dc-norn-a", "role": "norn-a"},
            {"hostname": "dc-norn-b", "role": "norn-b"},
            {"hostname": "dc-r1-01", "role": "r1"},
            {"hostname": "dc-r2-01", "role": "r2"},
            {"hostname": "dc-r3-01", "role": "r3"},
        ],
        "images": images,
        "external_requirements": {
            requirement_id: {
                "status": "blocked" if requirement_id == "resolver_trace" else "not_run",
                "status_zh": "阻断" if requirement_id == "resolver_trace" else "未运行",
                **({"reason_zh": "等待真实 Resolver Trace"} if requirement_id == "resolver_trace" else {"reason_zh": "等待外部验收"}),
                **({"blocked_by": "resolver_trace"} if requirement_id == "production_cutover" else {}),
            }
            for requirement_id in sorted(generator.REQUIRED_EXTERNAL_ACCEPTANCE_IDS)
        },
    }
    site_path = tmp_path / "site-manifest.json"
    _write_json(site_path, site)
    return site_path, release_path


def _build(tmp_path: Path, name: str = "out") -> Path:
    site, release = _fixture(tmp_path)
    return generator.build_delivery(site, release, PRODUCT_KIT, tmp_path / name, None, None)


def _archives(delivery: Path) -> list[Path]:
    return sorted((delivery / "03-主机包").glob("*.tar.gz"))


def _archive_files(archive: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with tarfile.open(archive, "r:gz") as handle:
        for member in handle.getmembers():
            if member.isfile():
                stream = handle.extractfile(member)
                assert stream is not None
                result[member.name] = stream.read()
    return result


def test_validate_inputs_rejects_role_mismatch_and_duplicate_host(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["hosts"][-1]["role"] = "wrapper"
    _write_json(site_path, site)
    site["release"]["manifest_sha256"] = hashlib.sha256(release_path.read_bytes()).hexdigest()
    with pytest.raises(generator.BundleError, match="role"):
        generator.validate_inputs(site_path, release_path)

    site_path, release_path = _fixture(tmp_path / "duplicate")
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["hosts"][-1]["hostname"] = site["hosts"][-2]["hostname"]
    _write_json(site_path, site)
    with pytest.raises(generator.BundleError, match="unique"):
        generator.validate_inputs(site_path, release_path)


def test_strict_oci_validation_rejects_wrong_release_digest(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    digest: dict[str, str] = {}
    generator._make_test_oci(archive, digest)
    with pytest.raises(generator.BundleError, match="does not equal release digest"):
        generator.validate_oci_archive(archive, "sha256:" + "0" * 64, {"os": "linux", "architecture": "amd64"})


def test_real_build_is_deterministic_and_named(tmp_path: Path):
    first = _build(tmp_path / "first")
    second = _build(tmp_path / "second")
    assert first.name == "resolver-identity-domain-center-easy-install-0.3.0-test"
    assert [item.name for item in _archives(first)] == [item.name for item in _archives(second)]
    assert [item.read_bytes() for item in _archives(first)] == [item.read_bytes() for item in _archives(second)]
    assert generator.verify_delivery(first, allow_blocked=True, structural_only=True)["verified"] is True


def test_host_archives_are_standalone_with_exact_entry_points(tmp_path: Path):
    delivery = _build(tmp_path)
    chinese = set(generator.CHINESE_ENTRY_POINTS)
    ascii_scripts = {f"scripts/{name}.sh" for name in generator.ASCII_ENTRY_POINTS}
    roles: set[str] = set()
    for archive in _archives(delivery):
        files = _archive_files(archive)
        prefix = archive.stem.removesuffix(".tar") + "/"
        metadata = json.loads(files[prefix + "expected-host.json"])
        roles.add(metadata["role"])
        required = {
            "README-请先阅读.txt", "expected-host.json", "wizard.py",
            "product-kit/common/lifecycle.py", "product-kit/common/load_images.py", "product-kit/common/role_entry.py",
            "config/.env", "config/inventory.env",
            f"product-kit/{metadata['role']}/docker-compose.yml",
            *chinese, *ascii_scripts,
        }
        assert required <= {name[len(prefix):] for name in files}
        assert files[prefix + "product-kit/common/load_images.py"] == IMAGE_LOADER_PATH.read_bytes()
        lock = json.loads(files[prefix + "images/image-lock.json"])
        assert lock["schema_version"] == generator.LOCK_SCHEMA
        for image in lock["images"]:
            assert prefix + "images/" + image["archive"] in files
            assert image["import_reference"] == generator._import_reference(
                image["reference"].split("@", 1)[0], image["digest"]
            )
            assert image["config_digest"].startswith("sha256:")
        inventory_env = files[prefix + "config/inventory.env"].decode()
        assert files[prefix + "config/.env"].decode() == inventory_env
        assert f"RI_FIELD_COMPOSE_PROJECT=ri-{metadata['hostname']}" in inventory_env
        assert f"RI_FIELD_DATA_DIR=/var/lib/resolver-identity/{metadata['hostname']}" in inventory_env
        for image in lock["images"]:
            assert image["import_reference"] in inventory_env
        assert files[prefix + f"product-kit/{metadata['role']}/PACKAGE-VERSION"] == b"0.3.0-test\n"
    assert roles == set(generator.ROLE_COUNTS)


def test_generated_standalone_rejects_removed_actual_host_override(tmp_path: Path):
    delivery = _build(tmp_path)
    archive = next(path for path in _archives(delivery) if path.name == "dc-r1-01.tar.gz")
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive, "r:gz") as handle:
        handle.extractall(extracted, filter="data")
    package = extracted / "dc-r1-01"
    completed = subprocess.run(
        [str(package / "开始安装.sh"), "--actual-host", "dc-r1-01", "--yes"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert completed.returncode == 2
    assert "unrecognized arguments: --actual-host" in completed.stderr


def test_image_lock_parser_and_full_repo_digest_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "rust.oci.tar"
    archive.write_bytes(b"offline image")
    reference = "registry.internal/domain-center/rust@sha256:" + "4" * 64
    import_reference = "registry.internal/domain-center/rust:ri-" + "4" * 16
    config_digest = "sha256:" + "5" * 64
    lock = {
        "schema_version": generator.LOCK_SCHEMA,
        "hostname": "dc-r1-01",
        "role": "r1",
        "images": [{"key": "rust", "reference": reference, "import_reference": import_reference, "digest": "sha256:" + "4" * 64, "config_digest": config_digest, "archive": archive.name, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}],
    }
    _write_json(tmp_path / "image-lock.json", lock)
    assert image_loader.parse_manifest(tmp_path / "image-lock.json") == [(archive, lock["images"][0]["archive_sha256"], reference, import_reference, config_digest)]

    calls: list[list[str]] = []
    loaded = False
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal loaded
        calls.append(command)
        if command[:4] == ["docker", "image", "ls", "--no-trunc"]:
            output = ""
        elif command[:3] == ["docker", "image", "inspect"] and not loaded:
            return subprocess.CompletedProcess(command, 1, "", "missing")
        elif command[:2] == ["docker", "load"]:
            loaded = True
            output = ""
        elif command[:3] == ["docker", "image", "inspect"]:
            output = json.dumps({"Id": config_digest, "RepoTags": [import_reference]})
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")
    monkeypatch.setattr(image_loader.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 0
    assert ["docker", "load", "--input", str(archive)] in calls
    assert not any("pull" in item for command in calls for item in command)

    monkeypatch.setattr(image_loader, "inspect_image", lambda _: {"Id": "sha256:" + "0" * 64, "RepoTags": []})
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 2


def test_image_loader_removes_only_new_imports_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "rust.oci.tar"
    archive.write_bytes(b"offline image")
    reference = "registry.internal/rust@sha256:" + "7" * 64
    import_reference = "registry.internal/rust:ri-" + "7" * 16
    config_digest = "sha256:" + "2" * 64
    _write_json(tmp_path / "image-lock.json", {
        "schema_version": generator.LOCK_SCHEMA,
        "hostname": "dc-r1-01",
        "role": "r1",
        "images": [{"key": "rust", "archive": archive.name, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "reference": reference, "import_reference": import_reference, "digest": "sha256:" + "7" * 64, "config_digest": config_digest}],
    })
    ids = iter([{"sha256:" + "1" * 64}, {"sha256:" + "1" * 64, "sha256:" + "2" * 64}])
    removed: list[set[str]] = []
    monkeypatch.setattr(image_loader, "image_ids", lambda: next(ids))
    monkeypatch.setattr(image_loader, "inspect_image", lambda _: {"Id": "sha256:" + "3" * 64, "RepoTags": []})
    monkeypatch.setattr(image_loader, "remove_images", lambda values: removed.append(values))
    monkeypatch.setattr(image_loader.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 2
    assert removed == [{import_reference, "sha256:" + "2" * 64}]


def test_image_lock_rejects_path_traversal(tmp_path: Path):
    _write_json(tmp_path / "image-lock.json", {
        "schema_version": generator.LOCK_SCHEMA,
        "hostname": "dc-r1-01",
        "role": "r1",
        "images": [{"key": "rust", "archive": "../outside.tar", "archive_sha256": "b" * 64, "reference": "registry.internal/rust@sha256:" + "4" * 64, "import_reference": "registry.internal/rust:ri-" + "4" * 16, "digest": "sha256:" + "4" * 64, "config_digest": "sha256:" + "5" * 64}],
    })
    with pytest.raises(image_loader.ImageError, match="安全"):
        image_loader.parse_manifest(tmp_path / "image-lock.json")


def test_wizard_enforces_exact_fqdn_and_packaged_identity(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(wizard, "run", lambda *args, **kwargs: pytest.fail("dispatch must not run"))
    wizard.check_expected_host("dc-r1-01", {"dc-r1-01.example"})
    wizard.check_expected_host("dc-r1-01.example", {"dc-r1-01.example"})
    with pytest.raises(wizard.InstallError) as raised:
        wizard.check_expected_host("dc-r1-01.example", {"dc-r1-01.other"})
    assert raised.value.code == "E002"
    assert "actual-host" not in wizard.build_parser().format_help()

    metadata = {"role": "r1", "expected_host": "dc-r1-01.example", "hostname": "dc-r1-01.example"}
    assert wizard.select_role(SimpleNamespace(role=None), metadata) == "r1"
    with pytest.raises(wizard.InstallError, match="固定角色"):
        wizard.select_role(SimpleNamespace(role="r2"), metadata)
    with pytest.raises(wizard.InstallError, match="禁止重复参数"):
        wizard.reject_duplicate_options(["--expected-host", "one", "--expected-host", "two"])


def test_wizard_answers_and_secret_paths_are_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    answers = tmp_path / "answers.json"
    _write_json(answers, {"role": "r1", "expected-host": "dc-r1-01.example", "yes": True})
    expanded = wizard.apply_answers(["install", "--answers", str(answers)])
    assert expanded[0] == "install"
    assert expanded[-1] == "--yes"
    assert expanded[expanded.index("--role") + 1] == "r1"
    assert expanded[expanded.index("--expected-host") + 1] == "dc-r1-01.example"
    with pytest.raises(wizard.InstallError, match="冲突"):
        wizard.apply_answers(["--answers", str(answers), "--role", "r2"])

    _write_json(answers, {"role": "r1", "password": "must-not-be-here"})
    with pytest.raises(wizard.InstallError, match="未知或秘密键"):
        wizard.apply_answers(["--answers", str(answers)])

    with pytest.raises(wizard.InstallError):
        wizard.validate_secret_dir(Path("/etc"))
    install_root = tmp_path / "install"
    (install_root / "data").mkdir(parents=True)
    (install_root / "data").chmod(0o700)
    with pytest.raises(wizard.InstallError):
        wizard.validate_secret_dir(install_root / "data", install_root)
    real = tmp_path / "real"
    real.mkdir()
    real.chmod(0o700)
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(wizard.InstallError):
        wizard.validate_secret_dir(link)

    with pytest.raises(lifecycle.LifecycleError, match="广泛目录"):
        lifecycle.check_secret_tree(Path("/etc"), "r1")


def test_show_mismatch_reports_but_never_bypasses(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(wizard.InstallError) as raised:
        wizard.check_expected_host("dc-r1-01.example", {"dc-r1-01.other"}, show_mismatch=True)
    assert raised.value.code == "E002"
    output = capsys.readouterr().out
    assert "期望 dc-r1-01.example" in output
    assert "实际 dc-r1-01.other" in output


def test_compose_requirements_use_real_norn_name_and_all_agent_tokens():
    assert 'compose(target, ["up", "-d", "norn-read-proxy"])' in LIFECYCLE_PATH.read_text(encoding="utf-8")
    r1 = (PRODUCT_KIT / "r1" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "RI_WRAPPER_UPSTREAMS: ${RI_WRAPPER_UPSTREAMS:?" in r1
    for role in ("r2", "r3"):
        text = (PRODUCT_KIT / role / "docker-compose.yml").read_text(encoding="utf-8")
        assert "RI_AGENT_WRAPPER_TOKEN_FILE: /run/secrets/agent_wrapper_token" in text
        assert "wrapper:" not in text
        assert "secrets/agent_wrapper_token" in lifecycle.REQUIRED_SECRETS[role]


def test_lifecycle_install_resumes_without_image_reload_and_honors_no_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    role_root = tmp_path / "product-kit" / "r1"
    role_root.mkdir(parents=True)
    (role_root / "PACKAGE-VERSION").write_text("0.3.0-test\n", encoding="utf-8")
    (role_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (role_root.parent / "common").mkdir()
    (role_root.parent / "common" / "load_images.py").write_text("# fake\n", encoding="utf-8")
    config = tmp_path / "config"
    config.mkdir()
    install_root = tmp_path / "install"
    data = install_root / "data" / "r1"
    (config / ".env").write_text(f"RI_FIELD_COMPOSE_PROJECT=dc-test-r1\nRI_FIELD_DATA_DIR={data}\n", encoding="utf-8")
    images = tmp_path / "images"
    images.mkdir()
    (images / "image-lock.json").write_text("{}\n", encoding="utf-8")
    runs: list[list[str]] = []
    monkeypatch.setattr(lifecycle, "preflight", lambda args, root: {"result": "passed", "status_zh": "通过"})
    monkeypatch.setattr(lifecycle, "run", lambda command, **kwargs: runs.append(command) or subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(lifecycle, "compose", lambda target, action, check=True: subprocess.CompletedProcess(action, 0, "", ""))
    args = SimpleNamespace(install_root=install_root, expected_host="dc-r1-01", role="r1", images=images, config_dir=config, secret_dir=tmp_path / "secrets", no_start=True)
    lifecycle.install(args, role_root)
    lifecycle.install(args, role_root)
    state = json.loads((args.install_root / "state" / "install-state.json").read_text())
    assert state["status"] == "staged"
    assert state["activated"] is False
    assert state["release"] is None
    assert state["staged_release"].endswith("/releases/0.3.0-test")
    assert not (install_root / "current").exists()
    assert "images_loaded" in state["phases"]
    assert len([command for command in runs if "load_images.py" in " ".join(command)]) == 1
    assert len(list((args.install_root / "releases").iterdir())) == 1
    marker = json.loads((data / lifecycle.DATA_MARKER).read_text())
    assert marker["canonical_path"] == str(data)
    assert marker["install_id"] == state["install_id"]


def test_runtime_directories_follow_field_owner_modes_and_reject_drift(tmp_path: Path):
    install_root = tmp_path / "install"
    data = install_root / "data" / "r1"
    args = SimpleNamespace(install_root=install_root, expected_host="dc-r1-01", role="r1")
    lifecycle._ensure_owned_data(data, args, {"install_id": "install-1"})
    assert (data.stat().st_mode & 0o7777) == 0o750
    assert ((data / "knot-cache").stat().st_mode & 0o7777) == 0o750
    assert ((data / "trace").stat().st_mode & 0o7777) == 0o2770
    data.chmod(0o700)
    with pytest.raises(lifecycle.LifecycleError, match="0750") as raised:
        lifecycle._ensure_owned_data(data, args, {"install_id": "install-1"})
    assert raised.value.code == "DATA006"


def test_wrapper_upstreams_reject_local_bind_shadow_and_malformed_endpoints(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(lifecycle, "local_host_names", lambda: {"dc-r1-01", "dc-r1-01.example"})
    monkeypatch.setattr(lifecycle, "_local_ips", lambda: {"127.0.0.1", "192.0.2.10"})
    for upstream in ("", "udp://localhost:53", "udp://127.0.0.1:53", "udp://dc-r1-01:53", "udp://192.0.2.10:53", "udp://198.51.100.10:1053", "udp://resolver:not-a-port"):
        with pytest.raises(lifecycle.LifecycleError) as raised:
            lifecycle._validate_wrapper_upstreams({"RI_WRAPPER_UPSTREAMS": upstream, "DNS_BIND_ADDRESS": "192.0.2.10"})
        assert raised.value.code == "SEC108"
    lifecycle._validate_wrapper_upstreams({"RI_WRAPPER_UPSTREAMS": "udp://198.51.100.20:53,tcp://198.51.100.20:53", "DNS_BIND_ADDRESS": "192.0.2.10"})


def test_activate_rechecks_machine_identity_before_destructive_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "install"
    target = root / "releases" / "v2"
    (target / "config").mkdir(parents=True)
    (target / "config" / ".env").write_text("RI_FIELD_COMPOSE_PROJECT=test\n", encoding="utf-8")
    _write_json(target / ".installed.json", {"install_id": "install-1", "host": "dc-r1-01", "role": "r1"})
    (root / "state").mkdir(parents=True)
    _write_json(root / "state" / "install-state.json", {
        "host": "dc-r1-01", "role": "r1", "install_id": "install-1", "status": "staged",
        "staged_release": str(target), "machine_id": "a" * 32,
    })
    monkeypatch.setattr(lifecycle, "host_matches", lambda expected: True)
    monkeypatch.setattr(lifecycle, "_machine_id", lambda: "b" * 32)
    args = SimpleNamespace(install_root=root, expected_host="dc-r1-01", role="r1", secret_dir=None)
    with pytest.raises(lifecycle.LifecycleError, match="machine-id") as raised:
        lifecycle.activate(args)
    assert raised.value.code == "HOST006"


def test_failed_activation_stops_partial_release_and_restarts_previous(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "install"
    target = root / "releases" / "v2"
    previous = root / "releases" / "v1"
    for release in (target, previous):
        (release / "config").mkdir(parents=True)
        (release / "config" / ".env").write_text("RI_FIELD_COMPOSE_PROJECT=test\n", encoding="utf-8")
    lifecycle.set_current(root, target)
    commands: list[tuple[Path, list[str], bool]] = []
    monkeypatch.setattr(lifecycle, "compose", lambda release, action, check=True: commands.append((release, action, check)) or subprocess.CompletedProcess(action, 0, "", ""))
    monkeypatch.setattr(lifecycle, "start_ordered", lambda release, *args: commands.append((release, ["restart-ordered"], True)))

    restored = lifecycle._restore_previous_release(root, target, previous, "r1", None, root / "state.json")

    assert restored == str(previous)
    assert (root / "current").resolve() == previous
    assert commands == [
        (target, ["down", "--remove-orphans"], False),
        (previous, ["restart-ordered"], True),
    ]


def test_resolver_backup_uses_consistent_sqlite_snapshot_and_excludes_live_wal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    install_root = tmp_path / "install"
    target = install_root / "releases" / "v1"
    data = install_root / "data" / "r1"
    (target / "config").mkdir(parents=True)
    data.mkdir(parents=True)
    (target / "config" / ".env").write_text(f"RI_FIELD_DATA_DIR={data}\n", encoding="utf-8")
    database = data / "evidence-v2.db"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE evidence (value TEXT)")
    connection.execute("INSERT INTO evidence VALUES ('preserved')")
    connection.commit()
    (data / "ordinary.txt").write_text("included", encoding="utf-8")
    monkeypatch.setattr(lifecycle, "validate_active_install", lambda args: ({"install_id": "id"}, target))
    monkeypatch.setattr(lifecycle, "_validate_marker", lambda *args: None)
    output = tmp_path / "backup"
    args = SimpleNamespace(install_root=install_root, expected_host="dc-r1-01", role="r1", output=output)
    lifecycle.backup(args)
    connection.close()

    archive = next(output.glob("*.tar.gz"))
    with tarfile.open(archive, "r:gz") as handle:
        names = handle.getnames()
        manifest = json.load(handle.extractfile("backup-manifest.json"))
        extracted = tmp_path / "snapshot.db"
        extracted.write_bytes(handle.extractfile("data/evidence-v2.db").read())
    assert "data/evidence-v2.db-wal" not in names
    assert "data/evidence-v2.db-shm" not in names
    assert manifest["database"]["method"] == "sqlite3_online_backup"
    assert manifest["database"]["integrity_check"] == "ok"
    with sqlite3.connect(extracted) as snapshot:
        assert snapshot.execute("SELECT value FROM evidence").fetchone() == ("preserved",)
    assert (output.stat().st_mode & 0o077) == 0
    assert (archive.stat().st_mode & 0o077) == 0


def test_resolver_backup_manifest_truthfully_records_absent_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    install_root = tmp_path / "install"
    target = install_root / "releases" / "v1"
    data = install_root / "data" / "r1"
    (target / "config").mkdir(parents=True)
    data.mkdir(parents=True)
    (target / "config" / ".env").write_text(f"RI_FIELD_DATA_DIR={data}\n", encoding="utf-8")
    monkeypatch.setattr(lifecycle, "validate_active_install", lambda args: ({"install_id": "id"}, target))
    monkeypatch.setattr(lifecycle, "_validate_marker", lambda *args: None)
    output = tmp_path / "backup"
    lifecycle.backup(SimpleNamespace(install_root=install_root, expected_host="dc-r1-01", role="r1", output=output))
    with tarfile.open(next(output.glob("*.tar.gz")), "r:gz") as handle:
        manifest = json.load(handle.extractfile("backup-manifest.json"))
    assert manifest["database"] == {"path": "data/evidence-v2.db", "status": "absent"}


def test_existing_nonempty_data_dir_is_never_claimed(tmp_path: Path):
    install_root = tmp_path / "install"
    data = install_root / "data" / "r1"
    data.mkdir(parents=True)
    (data / "existing.db").write_bytes(b"business data")
    args = SimpleNamespace(install_root=install_root, expected_host="dc-r1-01", role="r1")
    with pytest.raises(lifecycle.LifecycleError) as raised:
        lifecycle._ensure_owned_data(data, args, {"install_id": "new-install"})
    assert raised.value.code == "DATA002"
    assert not (data / lifecycle.DATA_MARKER).exists()


def test_norn_readiness_uses_authenticated_get_block_number_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    secret = tmp_path / "secrets" / "norn-tls"
    secret.mkdir(parents=True)
    for name in ("ca.crt", "client.crt", "client.key"):
        (secret / name).write_bytes(name.encode())
    loaded: list[tuple[str, str]] = []

    class Context:
        def load_cert_chain(self, cert: str, key: str) -> None:
            loaded.append((cert, key))

    class Response:
        status = 200
        headers = {"Content-Type": "application/grpc", "grpc-status": "0"}

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit == 4 * 1024 * 1024 + 1
            return b"\x00\x00\x00\x00\x02\x10\x07"

    requests: list[object] = []
    monkeypatch.setattr(lifecycle.ssl, "create_default_context", lambda cafile: Context())
    monkeypatch.setattr(lifecycle, "urlopen", lambda request, timeout, context: requests.append(request) or Response())
    env = {"RI_NORN_READ_HOSTNAME": "norn-read-a.example", "RI_NORN_READ_PORT": "8443"}

    assert lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "secrets") is True
    request = requests[0]
    assert request.full_url == "https://norn-read-a.example:8443/Blockchain/GetBlockNumber"
    assert request.method == "POST"
    assert request.data == b"\x00\x00\x00\x00\x00"
    assert request.headers["Content-type"] == "application/grpc"
    assert loaded == [(str(secret / "client.crt"), str(secret / "client.key"))]


def test_norn_readiness_fails_closed_for_missing_or_invalid_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env = {"RI_NORN_READ_HOSTNAME": "norn-read-a.example", "RI_NORN_READ_PORT": "8443"}
    with pytest.raises(lifecycle._NornProbeError) as missing:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "secrets")
    assert missing.value.code == "NORN_TLS_MISSING"

    secret = tmp_path / "invalid" / "norn-tls"
    secret.mkdir(parents=True)
    for name in ("ca.crt", "client.crt", "client.key"):
        (secret / name).write_bytes(b"material")
    monkeypatch.setattr(lifecycle.ssl, "create_default_context", lambda cafile: (_ for _ in ()).throw(lifecycle.ssl.SSLError("bad ca")))
    with pytest.raises(lifecycle._NornProbeError) as bad_ca:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "invalid")
    assert bad_ca.value.code == "NORN_TLS_CA_INVALID"

    class Context:
        def load_cert_chain(self, cert: str, key: str) -> None:
            raise lifecycle.ssl.SSLError("mismatch")

    monkeypatch.setattr(lifecycle.ssl, "create_default_context", lambda cafile: Context())
    with pytest.raises(lifecycle._NornProbeError) as mismatch:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "invalid")
    assert mismatch.value.code == "NORN_TLS_CERT_KEY_MISMATCH"


def test_norn_readiness_distinguishes_connection_http_and_malformed_grpc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    secret = tmp_path / "secrets" / "norn-tls"
    secret.mkdir(parents=True)
    for name in ("ca.crt", "client.crt", "client.key"):
        (secret / name).write_bytes(name.encode())

    class Context:
        def load_cert_chain(self, cert: str, key: str) -> None:
            return None

    monkeypatch.setattr(lifecycle.ssl, "create_default_context", lambda cafile: Context())
    env = {"RI_NORN_READ_HOSTNAME": "norn-read-a.example", "RI_NORN_READ_PORT": "8443"}
    monkeypatch.setattr(lifecycle, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("stopped")))
    with pytest.raises(lifecycle._NornProbeError) as stopped:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "secrets")
    assert stopped.value.code == "NORN_CONNECTION" and stopped.value.retryable

    class Response:
        status = 403
        headers = {"Content-Type": "text/plain"}
        def __enter__(self):
            return self
        def __exit__(self, *args: object) -> None:
            return None
        def read(self, limit: int) -> bytes:
            return b"denied"

    monkeypatch.setattr(lifecycle, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(lifecycle._NornProbeError) as rejected:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "secrets")
    assert rejected.value.code == "NORN_HTTP_REJECTED"

    Response.status = 200
    Response.headers = {"Content-Type": "application/grpc", "grpc-status": "0"}
    monkeypatch.setattr(lifecycle, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(lifecycle._NornProbeError) as malformed:
        lifecycle.readiness_probe("norn-a", "norn_ready", env, tmp_path / "secrets")
    assert malformed.value.code == "NORN_GRPC_INVALID"


def test_r1_start_is_ordered_readiness_gated_and_uses_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "release"
    (target / "config").mkdir(parents=True)
    (target / "config" / ".env").write_text("RI_FIELD_COMPOSE_PROJECT=test\n", encoding="utf-8")
    commands: list[list[str]] = []
    readiness: list[str] = []
    monkeypatch.setattr(lifecycle, "compose", lambda target, action, check=True: commands.append(action) or subprocess.CompletedProcess(action, 0, "", ""))
    monkeypatch.setattr(lifecycle, "_wait_readiness", lambda role, phase, env, secret: readiness.append(phase))
    state: dict[str, object] = {}
    lifecycle.start_ordered(target, "r1", {}, None, state, tmp_path / "state.json")
    assert commands == [
        ["up", "-d", "registry-sync"],
        ["up", "-d", "agent", "trace-adapter"],
        ["up", "-d", "trace-producer", "resolver"],
        ["--profile", "first-hop", "up", "-d", "wrapper"],
    ]
    assert readiness == ["registry_ready", "agent_trace_ready", "resolver_ready", "wrapper_shadow_ready"]


def test_support_bundle_redacts_structured_and_text_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = tmp_path / "install" / "state"
    state.mkdir(parents=True)
    _write_json(state / "install-state.json", {
        "status": "failed", "authorization": "Bearer top-secret-token",
        "rpc_url": "https://user:password@rpc.invalid/api?key=secret", "message_zh": "预检失败",
        "diagnostic": "Authorization: Basic dXNlcjpwYXNz\nCookie: sid=abc\npassword: hunter2\nTOKEN=env-secret\n"
                      "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123\n"
                      "-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----",
    })
    (state / "agent_private.key").write_text("PRIVATE-KEY-MATERIAL", encoding="utf-8")
    (state / "wrapper-token.txt").write_text("WRAPPER-TOKEN", encoding="utf-8")
    monkeypatch.setattr(lifecycle.shutil, "which", lambda command: None)
    output = tmp_path / "support"
    lifecycle.support(SimpleNamespace(output=output, expected_host="dc-r1-01", install_root=tmp_path / "install"))
    with tarfile.open(next(output.glob("support-*.tar.gz")), "r:gz") as handle:
        names = handle.getnames()
        payload = b"\n".join(handle.extractfile(member).read() for member in handle.getmembers() if member.isfile())
    assert not any("key" in name.lower() or "token" in name.lower() for name in names)
    for secret in (b"PRIVATE-KEY-MATERIAL", b"WRAPPER-TOKEN", b"top-secret-token", b"user:password", b"key=secret", b"dXNlcjpwYXNz", b"sid=abc", b"hunter2", b"env-secret", b"eyJhbGci", b"BEGIN PRIVATE KEY"):
        assert secret not in payload
    assert "预检失败".encode() in payload


def test_resolver_topology_and_r1_shadow_port():
    r1 = (PRODUCT_KIT / "r1" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "wrapper:" in r1
    assert "${DNS_BIND_ADDRESS:?required}:1053:1053/udp" in r1
    assert "${DNS_BIND_ADDRESS:?required}:1053:1053/tcp" in r1
    assert "profiles: [first-hop]" in r1
    for role in ("r2", "r3"):
        text = (PRODUCT_KIT / role / "docker-compose.yml").read_text(encoding="utf-8").lower()
        assert "wrapper:" not in text
        assert "ri_agent_wrapper_token_file: /run/secrets/agent_wrapper_token" in text
        assert "profiles: [first-hop]" not in text


def test_evidence_preserves_external_statuses_and_false_deployment_claims(tmp_path: Path):
    evidence = json.loads((_build(tmp_path) / "证据.json").read_text(encoding="utf-8"))
    assert evidence["checks"]["resolver_trace"]["status"] == "blocked"
    assert evidence["checks"]["resolver_trace"]["status_zh"] == "阻断"
    assert evidence["checks"]["production_cutover"]["status"] == "not_run"
    assert evidence["checks"]["production_cutover"]["status_zh"] == "未运行"
    assert evidence["real_server_deployed"] is False
    assert evidence["production_traffic_enabled"] is False
    assert evidence["delivery_ready"] is False


def test_mandatory_acceptance_ids_cannot_be_omitted(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    del site["external_requirements"]["real_oci"]
    _write_json(site_path, site)
    with pytest.raises(generator.BundleError, match="real_oci"):
        generator.validate_inputs(site_path, release_path)


def test_passed_external_status_requires_provenance_record(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["external_requirements"]["monitoring"] = {"status": "passed", "status_zh": "已通过"}
    _write_json(site_path, site)
    with pytest.raises(generator.BundleError, match="evidence"):
        generator.validate_inputs(site_path, release_path)


def test_passed_external_evidence_is_copied_and_verified_offline(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    source = tmp_path / "monitoring report.txt"
    source.write_bytes(b"external monitoring evidence\n")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["external_requirements"]["monitoring"] = {
        "status": "passed", "status_zh": "已通过",
        "evidence": {"path": source.name, "sha256": digest, "timestamp": "2026-08-02T00:00:00Z", "source_commit": "a" * 40, "host": "site", "role": "site", "provenance": "external test system"},
    }
    _write_json(site_path, site)
    delivery = generator.build_delivery(site_path, release_path, PRODUCT_KIT, tmp_path / "out", None, None)
    evidence = json.loads((delivery / "证据.json").read_text(encoding="utf-8"))
    record = evidence["checks"]["monitoring"]["evidence"]
    assert record["path"] == f"12-验收证据/external-{digest}.txt"
    assert record["provenance"].startswith("bundled-copy:")
    bundled = delivery / record["path"]
    assert bundled.read_bytes() == source.read_bytes()
    source.unlink()
    assert generator.verify_delivery(delivery, allow_blocked=True, structural_only=True)["verified"]


def test_failed_external_status_does_not_require_fabricated_evidence(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["external_requirements"]["monitoring"] = {"status": "failed", "status_zh": "失败", "reason_zh": "真实检查失败"}
    _write_json(site_path, site)
    delivery = generator.build_delivery(site_path, release_path, PRODUCT_KIT, tmp_path / "out", None, None)
    assert json.loads((delivery / "证据.json").read_text())["checks"]["monitoring"]["status"] == "failed"


def test_status_vocabulary_rejects_noncanonical_aliases(tmp_path: Path):
    for alias in ("pass", "success", "pending"):
        site_path, release_path = _fixture(tmp_path / alias)
        site = json.loads(site_path.read_text(encoding="utf-8"))
        site["external_requirements"]["capacity"] = {
            "status": alias,
            "status_zh": alias,
            "reason_zh": "非规范状态",
        }
        _write_json(site_path, site)
        with pytest.raises(generator.BundleError, match="unsupported or inconsistent status"):
            generator.validate_inputs(site_path, release_path)


def test_strict_oci_requires_matching_import_reference_annotation(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    site["images"]["rust"]["repository"] = "registry.internal/domain-center/renamed-rust"
    _write_json(site_path, site)
    with pytest.raises(generator.BundleError, match="org.opencontainers.image.ref.name"):
        generator.validate_inputs(site_path, release_path)


def test_top_level_delivery_and_offline_recipient_verifier(tmp_path: Path):
    delivery = _build(tmp_path)
    assert set(generator.TOP_LEVEL_DIRECTORIES) <= {path.name for path in delivery.iterdir() if path.is_dir()}
    for name in ("SHA256SUMS", "recipient-verify.sh"):
        assert (delivery / name).is_file()
    assert not (delivery / "SHA256SUMS.sig").exists()
    assert not (delivery / "release-public-key.pem").exists()
    completed = subprocess.run([str(delivery / "recipient-verify.sh")], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert completed.returncode != 0
    assert "unsigned" in completed.stderr
    structural = subprocess.run([str(delivery / "recipient-verify.sh"), "--structural-only"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert structural.returncode == 0
    assert "STRUCTURAL ONLY" in structural.stdout
    assert "NOT RELEASE READY" in structural.stdout
    with pytest.raises(generator.BundleError, match="authenticity"):
        generator.verify_delivery(delivery, allow_blocked=True)
    diagnostic = generator.verify_delivery(delivery, allow_blocked=True, structural_only=True)
    assert diagnostic["release_authentic"] is False
    assert diagnostic["verification_mode"] == "structural_only"


def test_deterministic_across_umask(tmp_path: Path):
    site, release = _fixture(tmp_path / "fixture")
    script = f'''import importlib.util, pathlib, os
spec=importlib.util.spec_from_file_location("g", {str(GENERATOR_PATH)!r})
g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
os.umask(int(os.environ["BUILD_UMASK"], 8))
g.build_delivery(pathlib.Path({str(site)!r}), pathlib.Path({str(release)!r}), pathlib.Path({str(PRODUCT_KIT)!r}), pathlib.Path(os.environ["OUT"]), None, None)
'''
    outputs = []
    for mask in ("0022", "0077"):
        out = tmp_path / f"out-{mask}"
        subprocess.run([sys.executable, "-c", script], check=True, env={**os.environ, "BUILD_UMASK": mask, "OUT": str(out)})
        delivery = out / "resolver-identity-domain-center-easy-install-0.3.0-test"
        outputs.append({path.relative_to(delivery).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in delivery.rglob("*") if path.is_file()})
    assert outputs[0] == outputs[1]


def test_signed_verify_requires_external_pin_for_authenticity(tmp_path: Path):
    openssl = pytest.importorskip("shutil").which("openssl")
    if openssl is None:
        pytest.skip("openssl unavailable")
    site, release = _fixture(tmp_path / "fixture")
    key = tmp_path / "key.pem"
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
    key.chmod(0o600)
    delivery = generator.build_delivery(site, release, PRODUCT_KIT, tmp_path / "out", key, None)
    with pytest.raises(generator.BundleError, match="authenticity"):
        generator.verify_delivery(delivery, allow_blocked=True)
    structural = generator.verify_delivery(delivery, allow_blocked=True, structural_only=True)
    assert structural["trust"] == "self_signed/untrusted"
    assert structural["release_authentic"] is False
    trusted = generator.verify_delivery(delivery, allow_blocked=True, trusted_public_key=delivery / "release-public-key.pem")
    assert trusted["trust"] == "trusted_pinned_key"
    assert trusted["release_authentic"] is True
    script_unpinned = subprocess.run([str(delivery / "recipient-verify.sh")], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert script_unpinned.returncode != 0
    assert "not a trust anchor" in script_unpinned.stderr
    external_key = tmp_path / "external-release-public-key.pem"
    external_key.write_bytes((delivery / "release-public-key.pem").read_bytes())
    script_trusted = subprocess.run([str(delivery / "recipient-verify.sh"), str(external_key)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert script_trusted.returncode == 0
    assert "release authenticity verified" in script_trusted.stdout
    wrong = tmp_path / "wrong.pem"
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(tmp_path / "wrong-key.pem")], check=True)
    subprocess.run([openssl, "pkey", "-in", str(tmp_path / "wrong-key.pem"), "-pubout", "-out", str(wrong)], check=True)
    with pytest.raises(generator.BundleError, match="pinned public key"):
        generator.verify_delivery(delivery, allow_blocked=True, trusted_public_key=wrong)
    with pytest.raises(generator.BundleError, match="fingerprint"):
        generator.verify_delivery(delivery, allow_blocked=True, trusted_fingerprint="0" * 64)


def test_wrapper_structure_scanner_handles_safe_and_unsafe_yaml_variants():
    safe = '''services:\n  agent:\n    environment:\n      RI_AGENT_WRAPPER_TOKEN_FILE: /run/secrets/agent_wrapper_token\n'''
    assert not generator._contains_wrapper_structure(safe)
    unsafe = [
        '''services:\n  "wrapper":\n    image: pinned\n''',
        '''services:\n  x:\n    entrypoint: ["/usr/local/bin/ri-wrapper"]\n''',
        '''services:\n  x:\n    command:\n      - /usr/local/bin/ri-wrapper\n''',
        '''services:\n  x:\n    profiles:\n      - "first-hop"\n''',
        '''services:\n  x:\n    profiles: ['first-hop']\n''',
        '''services:\n  x:\n    environment:\n      "RI_WRAPPER_UPSTREAMS": tcp://resolver:53\n''',
        '''services:\n  x:\n    ports:\n      - "${DNS_BIND_ADDRESS}:1053:1053/udp"\n''',
    ]
    for text in unsafe:
        assert generator._contains_wrapper_structure(text), text


def test_required_release_tree_sbom_and_pdf_state_are_verified(tmp_path: Path):
    delivery = _build(tmp_path)
    assert set(generator.TOP_LEVEL_DIRECTORIES) == {path.name for path in delivery.iterdir() if path.is_dir()}
    spdx = json.loads((delivery / "04-软件物料清单/site.spdx.json").read_text())
    assert spdx["comment"] == "release.version=0.3.0-test;source.git.commit=" + "a" * 40
    evidence = json.loads((delivery / "证据.json").read_text())
    assert evidence["pdf"]["ready"] is False
    assert not list((delivery / "05-PDF手册").glob("*.pdf"))


def test_r2_r3_have_no_wrapper_but_use_shared_rust_image():
    for role in ("r2", "r3"):
        text = (PRODUCT_KIT / role / "docker-compose.yml").read_text(encoding="utf-8")
        assert "wrapper:" not in text
        assert "image: ${RI_IMAGE:?pin Rust image digest}" in text


def test_cli_exposes_unambiguous_output_parent_alias():
    help_text = subprocess.run([sys.executable, str(GENERATOR_PATH), "build", "--help"], check=True, text=True, stdout=subprocess.PIPE).stdout
    assert "--output-parent" in help_text
    normalized_help = "".join(help_text.splitlines()).replace(" ", "")
    assert "resolver-identity-domain-center-easy-install-<version>" in normalized_help


def test_documentation_contains_required_chinese_operator_guidance():
    docs = [REPO_ROOT / "docs" / "easy-install" / name for name in ("一页纸安装卡.md", "域名中心图文安装手册.md", "技术运维手册.md")]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in docs)
    for path in docs:
        assert len(path.read_text(encoding="utf-8")) >= 500
    for required in ("R1", "R2/R3", "Wrapper", "1053", "expected_host", "blocked", "not_run", "脱敏", "外部", "离线"):
        assert required in combined
