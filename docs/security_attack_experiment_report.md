# Formal Security Attack Experiment Report

## Scope and architecture invariant

This audit tests the hop-by-hop resolver identity architecture without changing its trust boundary:

- Wrapper directly authenticates only R1.
- R1 Agent verifies adjacent R2.
- R2 Agent verifies adjacent R3 or reaches an explicit terminal boundary.
- Signed evidence returns toward R1 and then Wrapper.
- Wrapper validates signed evidence; it does not directly query R2/R3 Indexer or Registry.
- DNS wire format is unchanged.

## Summary

The formal runner executes 13 defensive experiments. The production hardening pass added per-request challenge binding, persistent invalidation generations with compare-and-swap cache commits, final Registry rechecks, persistent Agent config high-water marks, and persistent EventWatcher cursor state. Exact cross-request chain replay and the previously characterized deterministic revocation races now fail closed.

A critical Merkle binding defect was found and fixed: production verification previously checked that an Indexer-supplied leaf belonged to the anchored root, but did not prove that the leaf represented the resolver object being verified. The verifier now recomputes the leaf from resolver ID key, object hash, object version, and status.

Signed-chain semantic validation was also hardened to reject orphan/spliced/duplicate downstream chains, omitted Agent-capable middle chains, terminal/resolver overlap, and inconsistent `final_result` assertions.

## Attack results

### IDX-001 — Malicious Indexer object tampering

- **Hypothesis:** A malicious Indexer changes resolver object JSON.
- **Steps:** Publish an anchored object; alter Indexer JSON without a matching canonical hash/signature.
- **Expected:** Reject before DNS release.
- **Actual:** Rejected by object hash metadata check.
- **Fail closed:** Yes.
- **Residual risk:** Indexer can deny service or withhold data.

### OBJ-001 — Old identity object replay

- **Hypothesis:** A signed version-1 object is replayed after the chain anchor advances.
- **Steps:** Keep old object; change trusted anchor version.
- **Expected:** `object_version_mismatch`.
- **Actual:** Rejected as expected.
- **Fail closed:** Yes.
- **Residual risk:** A still-current object remains usable until update/revocation finality.

### MRK-001 — Merkle proof substitution

- **Hypothesis:** A valid resolver-B proof under a shared root is substituted while verifying resolver A.
- **Steps:** Build two valid leaves under one root; replace A's proof row with B's valid proof.
- **Expected:** Reject because B's leaf is not the leaf derived from A's identity.
- **Actual:** `merkle_leaf_binding_mismatch` after hardening.
- **Fail closed:** Yes.
- **Residual risk:** Compromise of the trusted root publisher/admin is outside this verifier defense.

### CHN-001 — Exact unexpired chain replay

- **Hypothesis:** A signed chain for one Wrapper challenge cannot authorize another DNS request.
- **Steps:** Verify an intact signed chain with its original challenge, then replay it under a different challenge.
- **Expected:** Reject the replay with `verification chain challenge mismatch`.
- **Actual:** Original challenge accepted; different challenge rejected.
- **Fail closed:** Yes.
- **Residual risk:** Compromise of a legitimately bound Agent key still permits signing fresh challenges.

### KEY-001 — Agent key substitution

- **Hypothesis:** Replace R2 Agent public-key evidence and re-sign the subtree with an unauthorized key.
- **Steps:** Modify parent hop key evidence; sign downstream with attacker key; re-sign outer chain.
- **Expected:** Reject key ancestry/signature mismatch.
- **Actual:** SERVFAIL.
- **Fail closed:** Yes.
- **Residual risk:** Compromise of the legitimately bound Agent private key remains a trusted-principal compromise.

### SPL-001 — Downstream chain splice

- **Hypothesis:** Attach an intact/mutated subtree under an unrelated parent hop.
- **Steps:** Exercise orphan chain, wrong resolver ID, wrong endpoint, and duplicate downstream variants.
- **Expected:** Reject semantic parent-hop mismatch.
- **Actual:** All variants returned SERVFAIL.
- **Fail closed:** Yes.
- **Residual risk:** Colluding legitimately keyed Agents can make attributable false assertions.

### MID-001 — Malicious omission of middle chain

- **Hypothesis:** R1 reports an accepted Agent-capable R2 hop but omits R2's required downstream chain.
- **Steps:** Remove downstream chain and re-sign R1 chain.
- **Expected:** Reject incomplete signed topology.
- **Actual:** SERVFAIL after semantic completeness validation.
- **Fail closed:** Yes for reported Agent-capable topology.
- **Residual risk:** A completely hidden and unreported middle resolver cannot be inferred without independent topology evidence.

### TERM-001 — Terminal boundary injection

- **Hypothesis:** Declare an endpoint both terminal and a verified recursive hop.
- **Steps:** Add the recursive hop endpoint to `terminal_upstreams` and re-sign.
- **Expected:** Reject overlap.
- **Actual:** SERVFAIL.
- **Fail closed:** Yes.
- **Residual risk:** A legitimately keyed Agent can still lie about hidden runtime topology unless configuration is independently attested.

### HOP-001 — Forged nonexistent R2→R3 proof

- **Hypothesis:** Attach R3 directly beneath R1 without a parent hop introducing R3.
- **Steps:** Move the valid R3 subtree directly under the R1 chain and re-sign R1.
- **Expected:** Reject missing accepted parent hop.
- **Actual:** SERVFAIL.
- **Fail closed:** Yes.
- **Residual risk:** A compromised adjacent Agent key can issue malicious statements as that trusted principal.

### ROOT-001 — Root revoke/rollback defense

- **Hypothesis:** A revoked root continues authorizing cached/object evidence.
- **Steps:** Revoke the root and verify the endpoint.
- **Expected:** `root_status_invalid` / SERVFAIL.
- **Actual:** Rejected.
- **Fail closed:** Yes.
- **Residual risk:** Historical rollback on a fresh installation needs a trusted bootstrap/checkpoint policy.

### WEB3-001 — Reorganization handling

- **Hypothesis:** A block hash mismatch leaves pre-reorg cache trusted.
- **Steps:** Simulate branch hash replacement with FakeWeb3 and poll watcher.
- **Expected:** Reorg detected and trusted cache quarantined.
- **Actual:** Cache becomes `EXPIRED`, cursor rewinds, and canonical logs can replay.
- **Fail closed:** Yes after conservative hardening.
- **Residual risk:** A real orphan revoke is conservatively expired rather than semantically reversed. Watcher cursor and block hash are now persisted.

### CFG-001 — Config-version rollback

- **Hypothesis:** A lower signed Agent config version is replayed after a higher one.
- **Steps:** Accept current version, then return a lower version.
- **Expected:** SERVFAIL.
- **Actual:** Rejected in the live wrapper context.
- **Fail closed:** Yes in-process.
- **Residual risk:** Operators must preserve monotonic versions during coordinated configuration changes. High-water state is persisted across Wrapper restarts.

### RACE-001 — Concurrent revocation/query races

- **Hypothesis:** Revocation interleaves with cache/cold verification.
- **Steps:** Use deterministic thread events to pause (1) after a hot cache row read and (2) before cold `store_verified`; revoke/invalidate in the pause.
- **Expected:** Generation changes invalidate hot reads and prevent stale cold commits.
- **Actual:** Both deterministic races reject; no post-revocation `VERIFIED` row is committed.
- **Fail closed:** Yes.
- **Residual risk:** Revocation visibility remains bounded by RPC finality and EventWatcher confirmation policy.

## Implementation hardening applied

1. Merkle proof membership is now bound to the verified resolver object leaf.
2. Proof row root and proof JSON root must match the chain anchor root.
3. Reorg detection expires all trusted cache rows before replay/reconciliation and persists its cursor/hash.
4. Signed chain semantics now reject:
   - orphan downstream chains;
   - resolver/endpoint splice mismatches;
   - duplicate hops and downstream chains;
   - missing downstream chain for Agent-capable accepted hops;
   - terminal overlap with resolver hops/downstream chains;
   - inconsistent `final_result` and `chain_errors`.
5. A verified recursive upstream without an adjacent Agent URL is no longer silently reclassified as terminal; only explicitly configured terminal endpoints terminate the chain.
6. Production startup rejects missing distributed verification, HMAC object signatures, and missing pinned issuer keys.
7. Per-request challenges bind all nested Agent chain signatures to one Wrapper request.
8. Cache invalidation generations and final Registry rechecks close deterministic revocation/write races.

## Commands and actual results

```bash
python3 -m compileall src tests tools
```

PASS.

```bash
PYTHONPATH=src python3 tools/run_security_experiments.py --attack all --strict
```

PASS; 13 result records generated under `artifacts/security-audit/latest/`.

```bash
python3 -m pytest tests -q
```

PASS: `121 passed` with the production hardening and operational tests included; branch coverage is `71%`.

```bash
cd contracts && forge test -vvv
```

PASS: `14 passed, 0 failed, 0 skipped`.

```bash
docker-compose -f docker-compose.multi-resolver.yml config
```

PASS.

```bash
python3 tools/run_multi_resolver_e2e.py --scenario all
```

PASS: exit code 0, `"docker_multi_resolver_web3_e2e": "ok"`.

## Overall conclusion

The system fails closed for malicious Indexer object mutation, object version replay, Merkle proof substitution, key substitution, chain splice, forged downstream attachment, terminal overlap, omitted reported Agent-capable middle chains, revoked roots, in-process config rollback, and synthetic reorg cache trust.

The hardened production path prevents exact signed-chain reuse across requests, rejects config rollback after Wrapper restart, and closes the deterministic cache/revocation races covered by the test suite. Remaining guarantees are still bounded by EVM finality, trusted key custody, and truthful reporting by legitimately keyed Agents. The hop-by-hop architecture remains unchanged.
