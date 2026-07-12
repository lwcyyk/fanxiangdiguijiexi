# Production Architecture

## Supported deployment profile

The first production profile is a single Linux host running Docker Compose. It uses:

- an external EVM JSON-RPC endpoint and a deployed `ResolverIdentityRegistryV1`;
- one local DNS Wrapper;
- one first-hop Resolver Identity Agent, with HTTPS URLs for any remote downstream Agents;
- SQLite on a host-local Docker volume in WAL mode;
- an internal control network plus a separate egress network;
- Docker secrets for Agent, issuer, Admin, and Web3 private material.

This profile is not horizontally scalable. Multiple Wrapper replicas or multi-host SQLite mounts are unsupported. A later HA profile must replace SQLite repositories with a transactional database and use a durable queue/cursor for Registry events.

## Runtime flow

```text
DNS client
  -> Wrapper UDP/TCP
       |-- normal DNS query ------------------------> R1 resolver
       `-- random request challenge -> R1 Agent -> downstream Agents
                                        |              |
                                        `-> Indexer + EVM Registry

Wrapper releases the pending DNS response only when both paths succeed.
```

Every production request uses a fresh challenge. Each nested `VerificationChain` signs that challenge, its resolver identity, endpoint, configuration version, validity window, hop evidence, and downstream chains.

## Mandatory security invariants

- `RESOLVER_IDENTITY_ENVIRONMENT=production`.
- Web3 Registry mode; SQLite Registry mode is rejected.
- HMAC resolver-object signatures disabled; a pinned Ed25519 issuer trust bundle is required.
- Distributed Agent verification required; missing first-hop Agent configuration aborts startup.
- Production Agent has an Ed25519 private key supplied through a secret file.
- Admin API has a token and a dedicated Web3 publisher key.
- Endpoint bindings include address/name/URI, port, transport, SNI, and ALPN material.
- Cache writes use an invalidation generation compare-and-swap. Registry state is rechecked before commit.
- Agent config high-water marks and EventWatcher block cursor/hash survive process restarts.
- A detected reorg quarantines trusted cache evidence before replay.
- Registry chain ID and deployed runtime bytecode hash are pinned and checked at startup and readiness probes.
- Resolver and root revocations are permanent in the contract; the last Registry administrator cannot be removed.
- Production query decisions stay in bounded memory/metrics by default instead of writing SQLite per DNS request.

## Network exposure

Only DNS UDP/TCP, localhost-bound metrics, and localhost-bound Admin ports are published. Indexer and Agent APIs stay on the control network. Agent clients support a pinned CA and mTLS client certificate directly. Plain HTTP is accepted only for exact hosts in `RESOLVER_IDENTITY_AGENT_PLAINTEXT_HOSTS`; remote links must use HTTPS.

## Data and recovery

The `resolver-data` volume contains identity objects, proofs, cache state, administrative audit records, config high-water marks, and watcher cursor/heartbeat state. Schema versioning uses SQLite `user_version` and fails closed when a newer schema is opened by older code. `tools/db_admin.py backup` uses the SQLite online backup API, verifies integrity, emits SHA-256, and creates mode `0600` output. Private keys are not stored in the database and require a separate encrypted backup.

## Operational limits

- Availability is bounded by one host and one writable SQLite database.
- A valid hot cache can tolerate Indexer/RPC outages only until hard TTL.
- Registry finality is controlled by `RESOLVER_IDENTITY_WATCHER_CONFIRMATIONS`.
- A legitimately registered malicious resolver, compromised Agent key, or dishonest topology report remains outside the identity guarantee.
- Public authoritative DNS correctness remains outside scope; use DNSSEC separately where required.
