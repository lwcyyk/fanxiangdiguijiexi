from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(slots=True)
class AttackResult:
    experiment_id: str
    category: str
    hypothesis: str
    steps: list[str]
    expected: str
    actual: str
    fail_closed: bool | None
    residual_risk: str
    duration_ms: float


ATTACKS: dict[str, dict] = {
    "IDX-001": {"category": "malicious_indexer", "test": "tests/integration/test_negative_verification.py::test_indexer_tampering_fails_hash_metadata_check", "hypothesis": "Tampered Indexer object JSON cannot satisfy canonical object hash checks.", "expected": "Rejected before DNS release.", "residual": "Indexer can still deny service."},
    "OBJ-001": {"category": "object_replay", "test": "tests/integration/test_negative_verification.py::test_stale_object_version_replay_fails_closed", "hypothesis": "An old resolver object cannot replace a newer chain anchor.", "expected": "object_version_mismatch.", "residual": "A still-current object remains valid until update/revocation finality."},
    "MRK-001": {"category": "merkle_substitution", "test": "tests/integration/test_merkle_proof_verification.py::test_valid_proof_for_another_leaf_cannot_be_substituted", "hypothesis": "Another valid leaf under the same root cannot prove the target object.", "expected": "merkle_leaf_binding_mismatch.", "residual": "Root publisher/admin compromise remains outside this defense."},
    "CHN-001": {"category": "chain_replay", "test": "tests/security/test_chain_attack_matrix.py::test_request_challenge_prevents_exact_chain_reuse", "hypothesis": "An exact unexpired chain cannot authorize a request with a different Wrapper challenge.", "expected": "challenge mismatch rejection.", "residual": "A compromised legitimately bound Agent key remains able to sign fresh challenges."},
    "KEY-001": {"category": "key_substitution", "test": "tests/security/test_chain_attack_matrix.py::test_agent_key_substitution_with_unauthorized_key_fails_closed", "hypothesis": "Substituting an unauthorized downstream Agent key cannot authorize a valid subtree.", "expected": "SERVFAIL.", "residual": "Compromise of the legitimately bound private key remains out of scope."},
    "SPL-001": {"category": "chain_splice", "test": "tests/security/test_chain_attack_matrix.py::test_downstream_chain_splice_attacks_fail_closed", "hypothesis": "A signed downstream subtree cannot be spliced beneath the wrong parent hop.", "expected": "SERVFAIL for orphan/id/endpoint/duplicate variants.", "residual": "Colluding legitimately keyed Agents can make attributable false statements."},
    "MID-001": {"category": "omitted_middle", "test": "tests/security/test_chain_attack_matrix.py::test_accepted_agent_capable_hop_cannot_omit_middle_chain", "hypothesis": "An Agent-capable recursive hop cannot omit its required downstream chain.", "expected": "SERVFAIL.", "residual": "A fully hidden unreported resolver cannot be inferred without independent topology evidence."},
    "TERM-001": {"category": "terminal_injection", "test": "tests/security/test_chain_attack_matrix.py::test_terminal_boundary_cannot_overlap_recursive_hop", "hypothesis": "A recursive hop cannot also be declared terminal.", "expected": "SERVFAIL.", "residual": "A legitimately keyed Agent can lie about hidden runtime topology."},
    "HOP-001": {"category": "forged_downstream", "test": "tests/security/test_chain_attack_matrix.py::test_valid_r3_chain_cannot_be_attached_directly_under_r1", "hypothesis": "R3 evidence cannot be attached directly under R1 without an introducing R1->R3 hop.", "expected": "SERVFAIL.", "residual": "Compromised adjacent Agent keys remain trusted principals."},
    "ROOT-001": {"category": "root_rollback", "test": "tests/integration/test_negative_verification.py::test_root_revoked_fails_closed", "hypothesis": "A revoked root cannot authorize resolver evidence.", "expected": "root_status_invalid.", "residual": "Historical rollback after a fresh-install bootstrap needs trusted checkpoint policy."},
    "WEB3-001": {"category": "reorg", "test": "tests/unit/test_event_watcher.py::test_poll_web3_events_rolls_back_on_reorg", "hypothesis": "A detected reorg quarantines trusted cache before replay.", "expected": "Cache becomes EXPIRED.", "residual": "Orphan invalidation reversal remains conservative and expires evidence."},
    "CFG-001": {"category": "config_rollback", "test": "tests/integration/test_agent_resolver_chain.py::test_config_version_rollback_or_replay_fails_closed", "hypothesis": "A lower Agent config version is rejected.", "expected": "SERVFAIL.", "residual": "Administrators must increment config versions atomically with resolver changes."},
    "RACE-001": {"category": "revocation_race", "test": "tests/security/test_revocation_race_characterization.py", "hypothesis": "Generation/CAS prevents stale allow and post-revocation VERIFIED writes.", "expected": "Concurrent verification fails closed.", "residual": "Safety is bounded by RPC finality and event-watcher confirmation policy."},
}


def run_attack(experiment_id: str) -> AttackResult:
    spec = ATTACKS[experiment_id]
    command = [sys.executable, "-m", "pytest", spec["test"], "-q"]
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    duration_ms = (time.perf_counter() - started) * 1000
    output = sanitize((completed.stdout + completed.stderr).strip())
    passed = completed.returncode == 0
    return AttackResult(
        experiment_id=experiment_id,
        category=spec["category"],
        hypothesis=spec["hypothesis"],
        steps=["Run the focused defensive regression/characterization test.", f"pytest target: {spec['test']}"],
        expected=spec["expected"],
        actual=("PASS: " if passed else "FAIL: ") + output[-800:],
        fail_closed=passed,
        residual_risk=spec["residual"],
        duration_ms=round(duration_ms, 3),
    )


def sanitize(value: str) -> str:
    return "".join(char if char in "\n\t" or 32 <= ord(char) < 127 else "?" for char in value)[:4000]


def markdown(results: list[AttackResult]) -> str:
    lines = ["# Security Attack Experiment Summary", "", "| ID | Category | Expected | Actual | Fail closed |", "|---|---|---|---|---|"]
    for result in results:
        actual = result.actual.replace("\n", " ").replace("|", "\\|")
        lines.append(f"| {result.experiment_id} | {result.category} | {result.expected} | {actual} | {result.fail_closed} |")
    lines.extend(["", "## Residual risks", ""])
    lines.extend(f"- **{result.experiment_id}**: {result.residual_risk}" for result in results)
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run formal resolver identity security experiments")
    parser.add_argument("--attack", default="all", help="attack ID or all")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--strict", action="store_true", help="return nonzero when any defensive experiment fails")
    parser.add_argument("--output-dir", default="artifacts/security-audit/latest")
    args = parser.parse_args()
    if args.list:
        print("\n".join(f"{key}\t{value['category']}" for key, value in ATTACKS.items()))
        return
    selected = list(ATTACKS) if args.attack == "all" else [args.attack]
    unknown = [item for item in selected if item not in ATTACKS]
    if unknown:
        raise SystemExit(f"unknown attack: {unknown[0]}")
    results = [run_attack(item) for item in selected]
    output_dir = (ROOT / args.output_dir).resolve()
    if ROOT not in output_dir.parents:
        raise SystemExit("output directory must be inside project root")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(json.dumps([asdict(result) for result in results], ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "summary.md").write_text(markdown(results), encoding="utf-8")
    print(json.dumps({"security_experiments": "complete", "results": [asdict(result) for result in results]}, ensure_ascii=False, indent=2))
    if args.strict and any(result.actual.startswith("FAIL:") for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
