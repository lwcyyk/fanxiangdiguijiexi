from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
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
                **({"reason_zh": "等待真实 Resolver Trace"} if requirement_id == "resolver_trace" else {}),
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
    assert generator.verify_delivery(first, allow_blocked=True)["verified"] is True


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
            f"product-kit/{metadata['role']}/docker-compose.yml",
            *chinese, *ascii_scripts,
        }
        assert required <= {name[len(prefix):] for name in files}
        lock = json.loads(files[prefix + "images/image-lock.json"])
        assert lock["schema_version"] == generator.LOCK_SCHEMA
        for image in lock["images"]:
            assert prefix + "images/" + image["archive"] in files
            assert image["import_reference"] == generator._import_reference(
                image["reference"].split("@", 1)[0], image["digest"]
            )
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
    lock = {
        "schema_version": generator.LOCK_SCHEMA,
        "hostname": "dc-r1-01",
        "role": "r1",
        "images": [{"key": "rust", "reference": reference, "digest": "sha256:" + "4" * 64, "archive": archive.name, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}],
    }
    _write_json(tmp_path / "image-lock.json", lock)
    assert image_loader.parse_manifest(tmp_path / "image-lock.json") == [(archive, lock["images"][0]["archive_sha256"], reference)]

    calls: list[list[str]] = []
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[:4] == ["docker", "image", "ls", "--no-trunc"]:
            output = ""
        elif command[:3] == ["docker", "image", "inspect"]:
            output = json.dumps([reference])
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")
    monkeypatch.setattr(image_loader.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 0
    assert ["docker", "load", "--input", str(archive)] in calls
    assert not any("pull" in item for command in calls for item in command)

    monkeypatch.setattr(image_loader, "inspect_digests", lambda _: {"other.invalid/rust@" + lock["images"][0]["digest"]})
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 2


def test_image_loader_removes_only_new_imports_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "rust.oci.tar"
    archive.write_bytes(b"offline image")
    reference = "registry.internal/rust@sha256:" + "7" * 64
    _write_json(tmp_path / "image-lock.json", {
        "schema_version": generator.LOCK_SCHEMA,
        "images": [{"archive": archive.name, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "reference": reference}],
    })
    ids = iter([{"sha256:" + "1" * 64}, {"sha256:" + "1" * 64, "sha256:" + "2" * 64}])
    removed: list[set[str]] = []
    monkeypatch.setattr(image_loader, "image_ids", lambda: next(ids))
    monkeypatch.setattr(image_loader, "inspect_digests", lambda _: set())
    monkeypatch.setattr(image_loader, "remove_images", lambda values: removed.append(values))
    monkeypatch.setattr(image_loader.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(sys, "argv", [str(IMAGE_LOADER_PATH), str(tmp_path)])
    assert image_loader.main() == 2
    assert removed == [{reference, "sha256:" + "2" * 64}]


def test_image_lock_rejects_path_traversal(tmp_path: Path):
    _write_json(tmp_path / "image-lock.json", {
        "schema_version": generator.LOCK_SCHEMA,
        "images": [{"archive": "../outside.tar", "archive_sha256": "b" * 64, "reference": "registry.internal/rust@sha256:" + "4" * 64}],
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
    assert state["status"] == "complete"
    assert state["activated"] is False
    assert "images_loaded" in state["phases"]
    assert len([command for command in runs if "load_images.py" in " ".join(command)]) == 1
    assert len(list((args.install_root / "releases").iterdir())) == 1
    marker = json.loads((data / lifecycle.DATA_MARKER).read_text())
    assert marker["canonical_path"] == str(data)
    assert marker["install_id"] == state["install_id"]


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
        assert "wrapper_token" not in text
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


def test_user_status_vocabulary_allowed_but_all_mandatory_must_pass(tmp_path: Path):
    site_path, release_path = _fixture(tmp_path)
    site = json.loads(site_path.read_text(encoding="utf-8"))
    for check in site["external_requirements"].values():
        check.clear()
        check.update({"status": "passed", "status_zh": "已通过"})
    site["external_requirements"]["capacity"] = {"status": "pending", "status_zh": "待验收"}
    _write_json(site_path, site)
    delivery = generator.build_delivery(site_path, release_path, PRODUCT_KIT, tmp_path / "out", None, None)
    evidence = json.loads((delivery / "证据.json").read_text(encoding="utf-8"))
    assert evidence["checks"]["capacity"]["status"] == "pending"
    assert evidence["delivery_ready"] is False


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
    assert completed.returncode == 0
    assert "signature=absent trust=unsigned" in completed.stdout


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
    structural = generator.verify_delivery(delivery, allow_blocked=True)
    assert structural["trust"] == "self_signed/untrusted"
    trusted = generator.verify_delivery(delivery, allow_blocked=True, trusted_public_key=delivery / "release-public-key.pem")
    assert trusted["trust"] == "trusted_pinned_key"
    wrong = tmp_path / "wrong.pem"
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(tmp_path / "wrong-key.pem")], check=True)
    subprocess.run([openssl, "pkey", "-in", str(tmp_path / "wrong-key.pem"), "-pubout", "-out", str(wrong)], check=True)
    with pytest.raises(generator.BundleError, match="pinned public key"):
        generator.verify_delivery(delivery, allow_blocked=True, trusted_public_key=wrong)
    with pytest.raises(generator.BundleError, match="fingerprint"):
        generator.verify_delivery(delivery, allow_blocked=True, trusted_fingerprint="0" * 64)


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
