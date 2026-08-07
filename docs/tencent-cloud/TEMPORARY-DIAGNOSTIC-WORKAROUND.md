# TEMPORARY_DIAGNOSTIC_WORKAROUND — registry_max_staleness_seconds=120

- **Status**: TEMPORARY — NOT a core fix
- **Date**: 2026-08-06
- **Applied by**: Diagnostic procedure per user directive (Step 2 of 7-step plan)
- **Will be reverted**: After Step 4 code fix is deployed (Step 7)

## Why this exists

`ri-registry-sync` captures `unix_time()` at the START of `reconcile()` before the Norn
chain adapter read, which takes ~42–44 seconds in the Tencent Cloud lab environment.
The stale timestamp is then written as `registry_last_success_epoch` in the evidence
database. With the designed `RI_REGISTRY_MAX_STALENESS_SECONDS=45`, the agent has at
most a ~1–3 second window per ~44s cycle to see a fresh heartbeat — which means it
effectively always returns 503 "Registry snapshot heartbeat is stale".

## What this workaround does

Increases `RI_REGISTRY_MAX_STALENESS_SECONDS` from 45 to 120 in the resolver `.env`
files on R1 (1.13.159.107), R2 (118.195.130.7), and R3 (118.195.189.105). This
masks the timing bug so the agent /readyz gate can pass, which unblocks the
deployment verification steps.

## What this workaround does NOT do

- Does NOT fix the root cause (stale timestamp semantics in ri-registry-sync)
- Does NOT change any frozen artifact binary
- Is NOT a permanent configuration

## Root cause fix

The proper fix is in Step 4–6 of the plan:
1. Separate `reconcile_started_at` from `reconciled_at` in `ri-registry-sync`
2. Capture fresh `unix_time()` after Norn read + snapshot validation + SQLite commit succeeds
3. Use the post-commit timestamp for the heartbeat
4. Keep snapshot, heartbeat, and cache_generation in the same transaction
5. Failed sync must never refresh the heartbeat

## Reversion

This workaround will be reverted in Step 7 after the rebuilt RC image is deployed.
