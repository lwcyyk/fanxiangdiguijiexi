# API Specification

## Wrapper

### `POST /dns-query`

Request body: DNS wire-format message. Header `Content-Type: application/dns-message`.

Response: DNS wire-format message. Success returns the original upstream response; verification failure returns a `SERVFAIL` wire response.

### `POST /v1/verify/resolver`

Request:

```json
{
  "endpoint": {"ip": "1.1.1.1", "port": 53, "transport": "udp"}
}
```

Response:

```json
{
  "accepted": true,
  "status": "VERIFIED",
  "resolver_id": "operator/resolver",
  "reasons": [],
  "evidence": {
    "resolver_id_key": "0x...",
    "object_hash": "0x...",
    "state_root": "0x...",
    "agent_key_algorithm": "ed25519",
    "agent_key_id": "agent-key-01"
  }
}
```

### `POST /v1/verify/query`

Verifies supplied observed resolver endpoints and returns a decision object. Normal DNS request gating is performed by `/dns-query` or UDP/TCP wrapper listeners.

### `GET /v1/cache`

Returns trusted cache entries and states.

### `GET /v1/proofs/{request_id}`

Returns proof journal for a wrapper request.

### `GET /healthz`

Returns service health.

### `GET /metrics`

Returns text metrics. The current prototype exposes minimal liveness metrics; production metrics should include query counts, cache hit/miss, verification decisions, Agent latency, Web3 latency, and revocation counts.

## Indexer

- `GET /v1/lookup/ip/{ip}`
- `GET /v1/lookup/name/{name}`
- `GET /v1/resolvers/{resolver_id}`
- `GET /v1/resolvers/{resolver_id}/proof`
- `GET /v1/resolvers/{resolver_id}/status`
- `GET /v1/roots/{state_root}`

Indexer data is not trusted until verified against chain anchor, object signature, endpoint binding, and Merkle proof/root status.

## Admin

- `POST /v1/admin/operators`
- `POST /v1/admin/resolvers`
- `POST /v1/admin/resolvers/{id}/endpoints`
- `POST /v1/admin/resolvers/{id}/revoke`
- `POST /v1/admin/roots/publish`

The CLI/API publish flow may include Agent public key metadata in resolver object `attestation.agent`.

## Resolver Identity Agent

### `GET /v1/identity`

Returns signed local resolver identity and upstream state:

```json
{
  "schema_version": "resolver-identity-agent-v1",
  "resolver_id": "operator-a/r1",
  "endpoint": {"ip": "172.30.0.11", "port": 1053, "transport": "udp"},
  "upstreams": [{"ip": "172.30.0.12", "port": 1053, "transport": "udp"}],
  "config_version": "1",
  "health": "ok",
  "issued_at": 1760000000,
  "expires_at": 1760000030,
  "issuer": "resolver-agent",
  "key_id": "agent-key-01",
  "signature": "base64:ed25519:..."
}
```

### `GET /v1/upstreams`

Returns the same signed upstream/config data subset for diagnostics. The wrapper uses `/v1/verification-chain` for the main distributed trust path.

### `GET /v1/verification-chain`

Returns the Agent's signed adjacent-upstream verification evidence and any signed downstream Agent chains:

```json
{
  "schema_version": "resolver-identity-verification-chain-v1",
  "resolver_id": "operator-a/r1",
  "endpoint": {"ip": "172.30.0.11", "port": 1053, "transport": "udp"},
  "config_version": "1",
  "hops": [
    {
      "schema_version": "resolver-identity-hop-verification-v1",
      "from_resolver_id": "operator-a/r1",
      "from_endpoint": {"ip": "172.30.0.11", "port": 1053, "transport": "udp"},
      "upstream_endpoint": {"ip": "172.30.0.12", "port": 1053, "transport": "udp"},
      "upstream_resolver_id": "operator-a/r2",
      "accepted": true,
      "status": "VERIFIED",
      "reasons": [],
      "evidence": {
        "resolver_id_key": "0x...",
        "object_hash": "0x...",
        "state_root": "0x...",
        "agent_public_key": "<base64 raw public key>",
        "agent_key_algorithm": "ed25519"
      },
      "issued_at": 1760000000,
      "expires_at": 1760000030,
      "issuer": "resolver-agent",
      "key_id": "agent-key-01",
      "signature": "base64:ed25519:..."
    }
  ],
  "downstream_chains": [],
  "terminal_upstreams": [],
  "chain_errors": [],
  "final_result": true,
  "issued_at": 1760000000,
  "expires_at": 1760000030,
  "issuer": "resolver-agent",
  "key_id": "agent-key-01",
  "signature": "base64:ed25519:..."
}
```

Each Agent signs only its own adjacent-hop verification result and chain summary. Downstream chains are verified with Agent public keys carried by prior verified hop evidence.

### `POST /v1/verification-chain`

Production Wrapper requests use this challenged form:

```json
{"challenge": "wrapper-generated-random-value-at-least-32-characters"}
```

Every nested `VerificationChain` includes and signs the same `challenge`. A chain signed for another request is rejected. The GET form remains a non-production diagnostic compatibility path.

### `GET /healthz`

Returns Agent health.

### Legacy aliases

- `GET /v1/agent/identity`
- `GET /v1/agent/observed-resolvers`

- `GET /v1/agent/verification-chain`

These remain for compatibility with the early stub but are not the main spec path.

## Agent verification requirements

The wrapper MUST NOT trust Agent chain data until:

1. the first-hop resolver endpoint has passed normal identity verification;
2. the verified first-hop resolver object binds an Ed25519 Agent public key;
3. the first-hop `/v1/verification-chain` response verifies against that public key;
4. every signed hop result verifies against the Agent public key of the resolver that produced it;
5. every downstream chain verifies against the Agent public key carried in the previous accepted hop evidence;
6. `resolver_id`, `endpoint`, `issued_at`, `expires_at`, `final_result`, loop/max-depth, and chain-completeness checks pass.
