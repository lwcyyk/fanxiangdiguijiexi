# Real multi-resolver testbed

This testbed exercises the controlled DNS path:

```text
client
  -> local-wrapper UDP/TCP :1053
  -> resolver-r1 CoreDNS :1053
  -> resolver-r2 CoreDNS :1053
  -> local CoreDNS hosts answer for example.test, then external forward fallback
```

The DNS message format is unchanged. Resolver identity data is fetched out of band from Resolver Identity Agents.

## Services

`docker-compose.multi-resolver.yml` defines:

- `anvil`: local Ethereum JSON-RPC chain for `ResolverIdentityRegistryV1`.
- `resolver-r1`: CoreDNS first-hop forwarder. It forwards to `resolver-r2`.
- `resolver-r2`: CoreDNS upstream resolver. It serves `example.test A 203.0.113.10` locally and forwards other names externally.
- `agent-r1`: signed Resolver Identity Agent for R1.
- `agent-r2`: signed Resolver Identity Agent for R2; used by R1 Agent in hop-by-hop distributed verification.
- `indexer`: FastAPI indexer service over the shared SQLite database.
- `event-watcher`: Web3 event/log poller and cache reconciler over the shared SQLite database.
- `local-wrapper`: Python DNS wrapper on non-privileged host port `1053/udp` and `1053/tcp`.

The compose network uses static container IPs so identity endpoints can be bound to concrete observed resolver endpoints:

- R1: `172.30.0.11:1053/udp`
- R2: `172.30.0.12:1053/udp`
- Anvil: `172.30.0.20:8545`

Only Anvil RPC and wrapper DNS are mapped to host ports for E2E orchestration and client queries.

## Web3 registry injection

`tools/run_multi_resolver_e2e.py` performs the dynamic Web3 setup:

1. Starts base Compose services.
2. Waits for Anvil.
3. Builds and deploys `ResolverIdentityRegistryV1`.
4. Writes the deployed contract address to `docker/state/web3.env`.
5. Publishes resolver objects through `AdminPublisher` using `Web3RegistryBackend`.
6. Starts/recreates wrapper and event-watcher so they read the Web3 env file.

SQLite is used for Indexer objects, Merkle proofs, trusted cache, and audit logs. It is not the trusted registry in the Compose Web3 path.

## Agent discovery and validation

`local-wrapper` is configured only with the first-hop endpoint-to-Agent mapping, for example:

```text
--agent-base-urls 172.30.0.11:1053:udp=http://agent-r1:8010
```

R1 Agent is separately configured with R2 Agent's URL:

```text
RESOLVER_IDENTITY_AGENT_UPSTREAM_AGENT_BASE_URLS=172.30.0.12:1053:udp=http://agent-r2:8010
```

For each query path, distributed verification works hop by hop:

1. `local-wrapper` verifies R1 through Indexer and Web3 registry.
2. wrapper extracts R1 Agent Ed25519 public key from R1 resolver object attestation.
3. wrapper fetches `GET /v1/verification-chain` from R1 Agent.
4. R1 Agent verifies only adjacent upstream R2 through Indexer and Web3 registry, then signs `HopVerificationResult(R1 -> R2)`.
5. R1 Agent calls R2 Agent when R2 has a configured Agent URL.
6. R2 Agent verifies only its adjacent upstream. If the upstream is configured as authoritative/external terminal, R2 records it as `terminal_upstreams` and ends the chain.
7. Signed results bubble back R2 -> R1 -> wrapper.
8. wrapper validates R1's chain signature, every signed hop, downstream chain signatures, loop/max-depth constraints, and all `final_result` values.
9. wrapper releases the DNS response only when the full signed chain verifies.

The Agent signed payloads bind:

- `resolver_id`
- service `endpoint`
- adjacent `hops`
- downstream signed chains
- terminal authoritative/external upstreams
- `config_version`
- `issued_at` / `expires_at`
- `issuer` / `key_id`

The Agent does not modify DNS packets.

## Running

```bash
python3 tools/run_multi_resolver_e2e.py
```

The driver verifies:

- UDP `example.test A` returns `203.0.113.10` when R1/R2 are registered.
- TCP `example.test A` returns `203.0.113.10` when R1/R2 are registered.
- Hot cache query succeeds.
- R1 missing returns SERVFAIL.
- R2 missing returns SERVFAIL.
- Agent resolver id mismatch returns SERVFAIL.
- Agent unavailable returns SERVFAIL.
- Agent signature mismatch returns SERVFAIL.
- R2 chain revoke returns SERVFAIL after event-watcher/cache invalidation.
- Root revoke returns SERVFAIL.
- Agent config-version change invalidates old chain cache and re-verifies.

Manual query example:

```bash
dig @127.0.0.1 -p 1053 example.test A
```

Do not point system DNS at this wrapper; it is intentionally exposed on non-privileged port `1053` for local testing only.

## Additional automated tests

`tests/integration/test_agent_resolver_chain.py` covers:

- R1 and R2 both registered -> response released.
- R1 missing -> SERVFAIL.
- R2 missing -> SERVFAIL.
- R1 -> R2 -> R3 legacy recursive discovery compatibility path succeeds.
- R1 -> R2 -> R1 loop is rejected.
- Hop-by-hop distributed chain succeeds when R1 signs R1->R2 and R2 signs its downstream chain.
- Tampered downstream chain signature is rejected.
- Signed hop loop evidence is rejected.
- Agent public key mismatch is rejected.
- Agent returns wrong `resolver_id` -> SERVFAIL.
- Agent unavailable in strict mode -> SERVFAIL.
- Any resolver authentication failure after a successful DNS response -> SERVFAIL.
- Hot trusted cache avoids repeated Indexer cold-path access while preserving Agent trust evidence.
- R1 config version/upstream change invalidates old chain cache.
- Agent signature tampering and replay rejection.
