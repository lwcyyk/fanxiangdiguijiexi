# Multi-chain Registry Adapter Requirements

## Goal

Decouple `ri-registry-sync` from EVM JSON-RPC and provide one fail-closed
Registry adapter contract that can support EVM, Go-Norn, and future chains
without changing Wrapper, Agent, Trace Adapter, or SQLite consumers.

## Required capabilities

Every production adapter must provide:

1. A stable chain identity that cannot be inferred from a mutable RPC URL.
2. A pinned Registry locator and Registry implementation/schema identity.
3. A finalized or confirmation-derived checkpoint height and block hash.
4. Historical block-hash lookup for stored high-water-mark verification.
5. A complete Resolver/Root/Endpoint snapshot at, or cryptographically bound
   to, the accepted checkpoint.
6. Deterministic mapping into `RegistryReferenceV2`.
7. Fail-closed behavior for rollback, same-height hash changes, stale or
   mismatched state, duplicate endpoints, invalid signatures, and RPC
   disagreement.

## Adapters

### EVM

- Preserve the existing `eth_chainId`, runtime bytecode hash, `finalized`
  block, confirmation fallback, Resolver anchor, Root status, and Endpoint
  binding checks.
- Preserve the existing `RI_WEB3_*` variables as compatibility aliases.

### Go-Norn

- Use Go-Norn's `Blockchain` gRPC read API.
- Pin the genesis block hash because the API does not expose a chain ID.
- Read from at least two independent RPC endpoints in every mode. Production
  endpoints must use HTTPS and mTLS.
- Derive the checkpoint as the lowest observed head minus configured
  confirmations.
- Require both nodes to agree on genesis, checkpoint block hash, and the exact
  Registry snapshot value.
- Require the Registry value to be a signed
  `resolver-identity-norn-registry-snapshot-v1` full snapshot.
- Never call `SendTransactionWithData` from the runtime adapter.

### Any other chain

- Implement the read-only external adapter protocol instead of modifying the
  DNS data plane.
- Serve `GET /v1/registry/snapshot` and `GET /v1/blocks/{number}` from two
  independently operated sidecar instances over HTTPS and mTLS.
- Derive the checkpoint and Registry records from the native chain; do not
  accept caller-supplied normalized state as trusted input.
- Sign the normalized snapshot with a pinned Ed25519 adapter key.
- Reject HTTP for every External deployment, require mTLS, and reject
  redirects.
- Pin a native immutable chain identity, Registry locator, and schema hash.

## Compatibility

- Existing EVM environment names remain compatibility aliases.
- New deployment examples use only generic `RI_CHAIN_*` variables.
- If a new variable and its legacy EVM alias are both set, their values must
  be equal; conflicts fail startup.
- SQLite schema v2 EVM rows migrate in place to schema v3 without deletion.
- Registry references use explicit adapter/chain/locator/schema/checkpoint/
  finality fields plus typed adapter metadata. EVM, Norn, and External
  metadata cannot be substituted for one another.

## Failure conditions

The sync process must not update SQLite when:

- the adapter is unknown;
- production RPC transport is not TLS;
- fewer than two independent Norn RPC endpoints are configured;
- fewer than two independent external sidecar endpoints are configured;
- a configured pin is zero, malformed, or does not match the chain;
- independent Norn nodes disagree;
- the signed snapshot is expired, not active, or signed by an untrusted key;
- a snapshot checkpoint is ahead of the accepted checkpoint or has a different
  block hash;
- any signed identity, Resolver anchor, Root, or Endpoint binding differs;
- the stored finalized checkpoint is no longer canonical.
- external sidecars disagree on the snapshot or historical block hash.
- a selected adapter fails, even if another adapter is fully configured.

## Process boundary

- Registry Sync is the only runtime component allowed to load a chain adapter
  or contact chain/sidecar RPC endpoints.
- Agent and Wrapper read only the last trusted local SQLite snapshot.
- A failed reconciliation does not change Registry rows, checkpoint high-water
  metadata, last-success time, or cache generation.

## Non-goals

- A single universal transaction signer for unrelated chain account models.
- Treating probabilistic confirmations as deterministic finality.
- Trusting an unauthenticated Go-Norn write RPC in production.
- Claiming historical-state proof support where the underlying chain does not
  provide it.
- Claiming that every blockchain is automatically supported without a
  chain-specific sidecar that implements the standard protocol.
