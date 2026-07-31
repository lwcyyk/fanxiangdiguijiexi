# Multi-chain Registry Adapter Design

## Compatibility boundary

`ri-chain-adapter` owns all chain-specific RPC and state decoding. Its public
contract is:

```text
RegistryChainAdapter
  target() -> ChainTarget
  read_snapshot(identities, issuer_keys, now) -> ChainSnapshot
  block_hash(height) -> bytes32
```

`ChainSnapshot` contains one accepted checkpoint and normalized Resolver
records. `ri-registry-sync` performs the common signature, active-window,
rollback, same-height hash, and atomic SQLite update logic.

Adding a chain requires an adapter implementation and configuration parser. It
does not require changes to the DNS data plane.

## Chain target model

| Field | EVM | Go-Norn | External sidecar |
|---|---|---|---|
| adapter | `evm` | `norn` | `external` |
| chain identity | `eip155:<chain-id>` | `norn-genesis:<hash>` | native immutable identity |
| typed metadata | chain ID, contract, runtime hash | genesis, Registry address/key, signer pin | driver and signer pin |
| Registry locator | contract address | state address plus key | native channel/module/object |
| Registry schema identity | runtime Keccak-256 | snapshot schema SHA-256 | adapter/schema hash |
| checkpoint | `finalized` or confirmations | minimum head minus confirmations | native finalized checkpoint |

`RegistryReferenceV2` uses `chain_adapter`, `chain_identity`,
`registry_locator`, `registry_schema_hash`, checkpoint height/hash,
`finality_type`, state root, and snapshot generation for every adapter.
`adapter_metadata` is a tagged enum. It is impossible to serialize a Norn
genesis, Registry key, or signer as an EVM contract/runtime anchor.

SQLite schema v3 keeps the old EVM columns only for read compatibility, adds
neutral columns, and stores the typed reference as JSON. The v2-to-v3 migration
parses old EVM rows, derives their neutral target fields, rewrites typed JSON,
and does not delete Resolver data. No adapter downgrade or implicit EVM
fallback is performed.

## EVM flow

1. Obtain finalized checkpoint.
2. Verify `eth_chainId`.
3. Read runtime code at the checkpoint and verify its Keccak-256.
4. Read each Resolver anchor, Root status, and Endpoint owner at the same block.
5. Re-read the checkpoint hash before committing.

## Go-Norn flow

1. Query all configured nodes for head height.
2. Select `min(head) - confirmations`.
3. Query block 0 and the selected checkpoint from all nodes.
4. Require exact genesis and checkpoint hash agreement.
5. Read `registry_address/registry_key` from all nodes.
6. Require the exact same non-empty JSON value.
7. Verify the snapshot Ed25519 signature with the configured issuer bundle.
8. Verify schema, chain namespace, genesis, Registry locator, schema hash,
   validity interval, Root status, snapshot version, and checkpoint binding.
9. Normalize snapshot entries and compare them to every local signed identity.
10. Re-read the checkpoint hash before committing.

Go-Norn does not currently expose historical state or a state proof. The signed
snapshot binds the Registry state to an already observed checkpoint and the two
read nodes must agree. This is an explicit weaker capability than EVM
historical `eth_call`; it is surfaced as `signed-checkpoint-snapshot`, not
misrepresented as native historical state.

## External compatibility protocol

`ExternalRegistryAdapter` is the stable boundary for Fabric, Cosmos,
Substrate, permissioned chains, and future ledgers. Two fixed mTLS sidecars
expose the machine-readable contract in `external-adapter-openapi.yaml`.
Registry Sync rejects HTTP and redirects, requires exact signed snapshot
agreement, validates the native target pins and Merkle root, then asks both
sidecars for the checkpoint hash.

The sidecar is chain-specific: it owns native RPC, finality, proof and Registry
decoding. It cannot merely proxy an arbitrary JSON document. The Rust data
plane remains unchanged when a new driver is added.

## Extensibility rules

Future adapters must:

- implement the same trait;
- provide a unique lowercase adapter name;
- define an unambiguous chain identity;
- declare how Registry schema identity is pinned;
- normalize block hashes to lower-case `0x` plus 32 bytes;
- return only full, internally consistent snapshots;
- implement historical block-hash lookup;
- document finality and state-proof capability gaps.

Adapters that cannot meet the last two requirements are integration-only and
must be rejected when `RI_ENVIRONMENT=production`.
