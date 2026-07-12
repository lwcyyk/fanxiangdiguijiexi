# Stepwise Agent Verification Test Report

## Scope

This report covers the migration to stepwise identity discovery, adjacent-upstream identity verification, Ed25519-signed hop results, downstream signed chain return, and wrapper-side aggregate verification.

## Commands and results

### Python compilation

Command:

```bash
python3 -m compileall src tests tools
```

Result: **PASS**. Source, test, and tool modules compiled without syntax errors.

### Python tests

Command:

```bash
python3 -m pytest tests -q
```

Result: **PASS**.

```text
88 passed in 1.06s
```

The Agent chain integration file contains 30 passing tests, including new tamper, replay, boundary, loop, depth, and no-answer-leakage cases.

### Solidity/Foundry tests

Command:

```bash
cd contracts && forge test -vvv
```

Result: **PASS**.

```text
11 tests passed, 0 failed, 0 skipped
```

Covered contract behavior includes resolver publish/update/revoke, endpoint bind/unbind, root publish/revoke, authorization, version replay rejection, and invalid input rejection.

### Docker Compose configuration

Requested command:

```bash
docker compose -f docker-compose.multi-resolver.yml config
```

Result: **UNAVAILABLE IN THIS ENVIRONMENT**. The installed `docker` CLI does not include the Compose v2 plugin and returned `unknown shorthand flag: 'f'`.

Fallback command:

```bash
docker-compose -f /home/lwc/fanxiangdiguijiexi/docker-compose.multi-resolver.yml config
```

Result: **PASS** using Docker Compose v1. The rendered configuration has only the R1 Agent URL on the wrapper command. R2 Agent URL appears in R1 Agent configuration, not wrapper configuration.

### Docker/Anvil multi-resolver E2E

Command:

```bash
python3 tools/run_multi_resolver_e2e.py --scenario all
```

Result: **PASS** using Docker Compose v1.

```text
"docker_multi_resolver_web3_e2e": "ok"
```

The optimized runner completed all groups and performed final cleanup. It builds the Python service images once, keeps Anvil/CoreDNS running across scenarios, recreates scenario-dependent services only when a new Registry contract/DB baseline is required, and restarts only the affected Agent for Agent/configuration scenarios.

Observed scenario results:

- positive UDP, TCP, and hot-cache queries: PASS;
- R1 identity missing: SERVFAIL, PASS;
- R2 identity missing: SERVFAIL, PASS;
- R1 Agent resolver-id mismatch: SERVFAIL, PASS;
- R1 Agent unavailable: SERVFAIL, PASS;
- R1 Agent bad signature: SERVFAIL, PASS;
- positive query after all basic-state restores: PASS;
- R2 resolver revocation: SERVFAIL after revocation, PASS;
- R2 root revocation: SERVFAIL after revocation, PASS;
- R1 Agent config-version change: response reverified and released, PASS.

Selected measured scenario times:

```text
basic.positive                  0.31s
basic.r1-missing              36.97s
basic.r2-missing               0.09s
basic.agent-wrong-id          16.97s
basic.agent-unavailable        7.05s
basic.agent-bad-signature     16.70s
revocation.r2                  0.24s
revocation.root                1.37s
config-version.change          8.73s
```

Earlier failed runs exposed two orchestration defects that were fixed before the passing run:

1. `_reset_db` had lost its function declaration during an earlier edit.
2. R2 Agent had been started before the scenario-specific contract address was written, causing `contract address has no code`. The optimized runner now starts/recreates R2 Agent only after the current Web3 environment is written.

## Security scenarios covered by automated tests

- Wrapper has only first-hop R1 Agent URL.
- R1 `VerificationChain` signature tampering fails closed.
- R2 downstream chain signature tampering fails closed.
- R1->R2 `upstream_resolver_id` tampering fails closed.
- R2->R3 upstream endpoint tampering fails closed.
- `object_hash` tampering fails closed.
- `state_root` tampering fails closed.
- non-`ACTIVE` resolver status fails closed.
- non-`ACTIVE` root status fails closed.
- endpoint-binding mismatch evidence fails closed.
- expired hop evidence fails closed.
- config-version rollback/replay fails closed.
- R1->R2->R1 loop fails closed.
- max-depth overflow fails closed.
- unavailable Agent fails closed.
- Indexer failure without valid cache fails closed.
- Registry failure without valid cache fails closed.
- terminal authoritative/external endpoint can end a chain without resolver identity verification.
- terminal endpoint disguised as a resolver hop fails closed.
- rejected authentication returns SERVFAIL and does not leak the original DNS answer.
- tampered nested evidence cannot be accepted based only on a `VERIFIED` string.

## Architecture audit result

The active distributed path retains the required semantics:

- Wrapper directly verifies R1 only.
- Wrapper calls R1 Agent only.
- R1 Agent verifies adjacent R2.
- R2 Agent verifies adjacent R3 or records a configured terminal boundary.
- Each Agent signs its own adjacent hop and chain summary.
- Results return downstream-to-upstream and are aggregated by R1.
- Wrapper validates signatures, signer-key ancestry, evidence consistency, loop/max-depth, expiry, config rollback, and final result.

The older wrapper-driven recursive code remains only as an explicitly selected compatibility path (`distributed_verification=False`) because existing compatibility tests still reference it. Runtime construction defaults to distributed verification and Compose does not configure downstream Agent URLs on Wrapper.

## Current implementation vs. thesis wording

Recommended thesis wording:

> The local wrapper directly authenticates only the first-hop recursive/forwarding resolver. Each resolver-side Agent discovers and authenticates only its adjacent upstream recursive/forwarding resolver using Indexer material checked against the blockchain Registry. Each Agent signs its hop verification result and returns any downstream signed chain to the previous Agent. The first-hop Agent aggregates the observable recursive/forwarding chain. The wrapper verifies the signed chain and releases the pending DNS response only when every recursive/forwarding hop and adjacent relationship passes. Root, TLD, authoritative, and configured external terminal endpoints are outside resolver identity verification.

The Wrapper verifies structured signed evidence; it does not independently repeat R2/R3 Indexer or Registry queries.

## Remaining gaps

- Public-Internet automatic discovery of hidden resolvers remains intentionally unsupported.
- Authoritative DNS data authenticity, DNSSEC, resolver execution correctness, TEE/TPM, remote attestation, and query execution proofs remain intentionally out of scope.
- The legacy Docker Compose v1 image build remains the dominant one-time cost; scenario execution no longer rebuilds images repeatedly.
