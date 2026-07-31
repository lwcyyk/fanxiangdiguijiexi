# Go-Norn field delivery design

## Package boundaries

The management package contains command-only tooling. Offline signing runs
without a network. Publication uses a fixed Node A target through an
authenticated SSH tunnel; issuer and snapshot private keys remain in an
external security directory.

The Norn package runs one node and one Nginx mTLS proxy. Native gRPC is bound to
node loopback for local administration and SSH-tunneled publication. The proxy
allows only:

- `GetBlockNumber`
- `GetBlockByNumber`
- `ReadContractAddress`

Every other method, including `SendTransactionWithData`, returns 403. Node A
and B use separate hosts, data, consensus keys and TLS profiles.

The resolver package runs Registry Sync, Agent and Trace Adapter on every
resolver. Wrapper uses a `first-hop` Compose profile and is not enabled for
upstream R2/R3. Only Registry Sync has Norn adapter variables and network
access. Agent and Wrapper read the local SQLite volume.

## Release and data lifecycle

Programs are installed under:

```text
/opt/resolver-identity/releases/<version>/
/opt/resolver-identity/current
```

Data lives outside release directories. Installation is idempotent. A failed
health check restores only the previous `current` symlink. It never restores or
deletes Norn data, SQLite, a Registry snapshot or on-chain state. Ordinary
uninstall preserves releases and data; `--purge-data` additionally requires an
ownership marker created by the installer.

## Inventory and secrets

`inventory.example.yaml` is JSON-compatible YAML 1.2 so the renderer can use a
strict duplicate-key-safe standard-library parser. It contains no secret
values. `secret-requirements.json` names externally provisioned files and
profiles but never generates or copies them.

The renderer creates deterministic gzip/tar metadata, per-package checksum
files and release-wide checksums. It supports image delivery by immutable
internal registry references and optional pre-created offline Docker archives.
