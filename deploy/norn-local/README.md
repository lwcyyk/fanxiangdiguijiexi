# Local Go-Norn integration network

This directory starts two real Go-Norn nodes at pinned upstream commit
`a7be734ac2e829e2076d06d45719d2716abd3d72`.

The image applies the audited local patch
`patches/0001-rpc-dynamic-data-writer.patch`. Upstream allocates a fixed 1024-byte
Karmem writer and ignores serialization errors in `SendTransactionWithData`,
which silently removes Registry values larger than roughly 1 KiB. Upstream also
starts a restarted block syncer at height `-1` instead of the persisted chain
height. The combined patch adds a 4 MiB limit, dynamic allocation, explicit
error handling, and restart-safe synchronization without changing the
transaction or state format.

- Native gRPC write endpoints bind only to `127.0.0.1:45555` and `:45556`.
- Registry Sync reads through mTLS method-filtering proxies at
  `https://localhost:46555` and `https://localhost:46556`.
- Node keys, TLS keys, chain data, snapshots, and runtime environment files are
  generated locally and ignored by Git.
- The upstream `SendTransactionWithData` method uses a node consensus key and
  has no authorization. It is intentionally absent from both proxy allowlists.

Run the scripts from the repository root:

```bash
scripts/norn/00-build.sh
scripts/norn/01-initialize.sh
scripts/norn/02-start.sh
scripts/norn/03-prepare-snapshot.sh
scripts/norn/04-publish-and-sync.sh
scripts/norn/05-negative-tests.sh
```

Do not use this network or its generated keys as a production chain.
