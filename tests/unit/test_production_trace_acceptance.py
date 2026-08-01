from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_production_trace_acceptance",
    REPO_ROOT / "tools" / "run_production_trace_acceptance.py",
)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acceptance
SPEC.loader.exec_module(acceptance)


def test_failure_gate_disables_exactly_the_first_selected_endpoint():
    gate = acceptance.EndpointFailureGate()
    endpoint_a = ("127.0.0.3", 15353)
    endpoint_b = ("127.0.0.4", 15353)

    assert gate.should_drop(endpoint_a) is False
    gate.arm()
    assert gate.should_drop(endpoint_b) is True
    assert gate.should_drop(endpoint_a) is False
    assert gate.should_drop(endpoint_b) is True
    assert gate.triggered.is_set()
