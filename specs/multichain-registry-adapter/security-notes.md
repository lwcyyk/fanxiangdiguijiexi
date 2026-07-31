# Security Notes

## Go-Norn upstream boundary

The reviewed Go-Norn revision is
`a7be734ac2e829e2076d06d45719d2716abd3d72`.

Its gRPC server uses plaintext `grpc.NewServer`, exposes reflection, and does
not authenticate `Blockchain` requests. `SendTransactionWithData` signs using
the node's configured consensus private key. Therefore:

- never expose the native RPC port to untrusted networks;
- put read endpoints behind separate mTLS proxies or a private service mesh;
- deny the write RPC method at the proxy;
- use read-only non-consensus nodes for Registry Sync;
- never copy the consensus private key to a Registry Sync host;
- do not use the runtime adapter as a publisher.

## State proof limitation

`ReadContractAddress` returns current LevelDB state and accepts no block height.
Go-Norn also exposes no state proof in this API. The adapter compensates with:

- a signed full snapshot;
- a pinned genesis hash;
- a snapshot checkpoint bound to a real block hash;
- confirmation depth;
- two independent nodes with exact agreement.

This is suitable for controlled preproduction only. Production parity with EVM
requires an upstream read API that returns historical state plus a verifiable
state/transaction inclusion proof.

The pinned upstream revision can also retain malformed or empty transaction
data around a valid large-value publication. The Norn adapter treats
undecodable transactions as non-publications and continues scanning, but once
it decodes the configured Registry key it requires the operation and value to
match exactly. This avoids a trivial malformed-transaction denial of service
without accepting malformed state. The local compatibility patch is not a
general audit or repair of Go-Norn consensus and serialization.

## Key separation

The snapshot issuer Ed25519 key is not an EVM role key and is not a Go-Norn
consensus key. Offline snapshot signing and chain transaction submission must
remain separate operations. Runtime configuration pins the expected snapshot
issuer and key ID. Rotation requires publishing a newer generation signed by
the new key and explicitly changing both the trust bundle and signer pin; the
old signer is not accepted after rotation.

## External sidecar trust boundary

The generic protocol does not make an unsupported chain trustworthy by itself.
Each sidecar must derive its snapshot and checkpoint from the native chain,
enforce native finality, and retain historical block hashes. Registry Sync
requires two endpoint responses to agree and verifies an independently pinned
Ed25519 signature. Production endpoints use HTTPS; private deployments should
also configure `RI_EXTERNAL_TLS_*` mTLS material.

The HTTP client disables redirects. Snapshot JSON and target objects reject
unknown fields, so a response cannot dynamically select an arbitrary upstream.
External and Norn references contain only neutral chain identity, Registry
locator and schema pins; EVM chain/contract/runtime fields are EVM-only.

A sidecar that only republishes operator input, cannot resolve historical block
hashes, or cannot explain native finality is integration-only and must not be
described as a production adapter.
