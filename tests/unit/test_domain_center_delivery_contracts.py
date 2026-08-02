from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCHEMAS = REPO / "deploy" / "easy-install" / "schemas"
FINALIZER = REPO / "tools" / "finalize_domain_center_easy_install.py"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


finalizer = _load("finalize_domain_center_easy_install", FINALIZER)


def test_delivery_contract_schemas_are_present_and_closed():
    expected = {
        "preflight-result.schema.json",
        "install-state-v2.schema.json",
        "support-bundle-manifest.schema.json",
        "shadow-acceptance.schema.json",
    }
    assert {path.name for path in SCHEMAS.glob("*.json")} == expected
    for name in expected:
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        assert schema["$schema"].endswith("2020-12/schema")
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert "required" in schema
        assert not ({"password", "secret", "token", "private_key"} & set(schema["properties"]))


def test_contracts_enforce_status_vocabulary_and_false_flags():
    preflight = json.loads((SCHEMAS / "preflight-result.schema.json").read_text())
    assert preflight["properties"]["result"]["enum"] == ["passed", "failed"]
    assert preflight["properties"]["checks"]["items"]["properties"]["status"]["enum"] == ["passed", "failed"]
    install = json.loads((SCHEMAS / "install-state-v2.schema.json").read_text())
    assert install["properties"]["schema"]["const"] == "domain-center-install-state-v2"
    for name in ("support-bundle-manifest.schema.json", "shadow-acceptance.schema.json"):
        schema = json.loads((SCHEMAS / name).read_text())
        assert schema["properties"]["real_server_deployed"]["const"] is False
        assert schema["properties"]["production_traffic_enabled"]["const"] is False


def _evidence(source: str) -> dict[str, object]:
    return {
        "source_commit": source,
        "real_server_deployed": False,
        "production_traffic_enabled": False,
        "checks": {
            "local": {"status": "blocked", "reason_zh": "外部未执行"},
            "cutover": {"status": "not_run", "blocked_by": ["local"]},
        },
    }


def test_finalizer_rejects_false_flag_and_source_binding_violations(tmp_path: Path):
    source = "a" * 40
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    evidence = _evidence(source)
    finalizer._validate_source_binding(evidence, source, delivery)
    evidence["real_server_deployed"] = True
    with pytest.raises(finalizer.FinalizeError, match="real_server_deployed"):
        finalizer._validate_source_binding(evidence, source, delivery)
    evidence["real_server_deployed"] = False
    with pytest.raises(finalizer.FinalizeError, match="source_commit"):
        finalizer._validate_source_binding(evidence, "b" * 40, delivery)


def test_executed_evidence_requires_exact_hash_and_source(tmp_path: Path):
    source = "a" * 40
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    record = delivery / "external.json"
    record.write_text("{}\n", encoding="utf-8")
    evidence = _evidence(source)
    evidence["checks"] = {"external": {"status": "passed", "evidence": {
        "path": "external.json", "sha256": "0" * 64, "source_commit": source,
    }}}
    with pytest.raises(finalizer.FinalizeError, match="hash-mismatched"):
        finalizer._validate_source_binding(evidence, source, delivery)
    evidence["checks"]["external"]["evidence"]["sha256"] = finalizer._sha256(record)
    finalizer._validate_source_binding(evidence, source, delivery)
    evidence["checks"]["external"]["evidence"]["source_commit"] = "b" * 40
    with pytest.raises(finalizer.FinalizeError, match="source binding"):
        finalizer._validate_source_binding(evidence, source, delivery)


def test_finalizer_diff_allowlist_is_confined_to_evidence_roots():
    assert finalizer._allowed_evidence_path(Path("specs/domain-center-easy-install/test-summary.json"))
    assert finalizer._allowed_evidence_path(Path("artifacts/domain-center/site/evidence.json"))
    for path in (
        Path("tools/finalize_domain_center_easy_install.py"),
        Path("deploy/easy-install/site.json"),
        Path("src/resolver_identity/config.py"),
        Path("specs/domain-center-star-deployment/tasks.md"),
    ):
        assert not finalizer._allowed_evidence_path(path)
