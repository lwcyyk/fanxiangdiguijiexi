# Requirements — Resolver Identity Prototype

## Scope

The prototype implements an application-layer out-of-band identity verification path for recursive DNS resolvers while preserving normal DNS wire formats. The current runtime target is a controlled multi-hop recursive resolver chain using Docker Compose, local Anvil, a Solidity registry, SQLite Indexer, Resolver Identity Agents, and a local DNS verification wrapper.

The system verifies only resolvers that are observable through local configuration or through authenticated Resolver Identity Agent responses. It does not guess hidden middle resolvers.

## Functional requirements

### DNS wrapper

- The wrapper SHALL expose local UDP DNS and TCP DNS listeners.
- The wrapper SHALL expose a local DoH endpoint at `POST /dns-query`.
- The wrapper SHALL forward normal DNS wire-format queries to configured upstream resolvers without modifying the query payload.
- The wrapper SHALL hold upstream DNS responses in `PENDING_VERIFICATION` until all observed resolvers are verified.
- The wrapper SHALL release the original upstream DNS response only when every observed resolver verifies successfully.
- The wrapper SHALL return DNS `SERVFAIL` when verification fails and no verified fallback path is available.
- The wrapper SHALL preserve DNS answer contents when verification succeeds.

### Identity object

- The system SHALL define `ResolverAuthenticityObjectV1` with resolver identity, operator, endpoints, validity, status, version, issuer, key id, attestation, and signature fields.
- The object hash SHALL be SHA-256 over canonical JSON with `signature` removed.
- Endpoint lookup keys SHALL be:
  - `SHA256("ip:" + canonicalIP)`
  - `SHA256("name:" + normalizedName)`
  - `SHA256("resolver-id:" + normalizedResolverID)`
- Resolver objects MAY bind an Agent Ed25519 public key under `attestation.agent`:

```json
{
  "algorithm": "ed25519",
  "public_key": "<base64 raw public key>",
  "key_id": "agent-key-01"
}
```

### Indexer and registry

- The SQLite Indexer SHALL store full resolver objects, endpoint indexes, Merkle proofs, state roots, trusted cache rows, and audit logs.
- The Indexer SHALL be treated as untrusted by the verifier.
- The chain registry SHALL be the trusted anchor for object hash, resolver version, validity, status, endpoint binding, and root status.
- Runtime SHALL support both SQLite-backed prototype registry and Web3-backed `ResolverIdentityRegistryV1`; Docker Compose E2E SHALL use Web3/Anvil as trusted registry.
- Only `ACTIVE` resolvers with non-expired objects, valid endpoint bindings, valid object signatures, valid Merkle proof/root status, and matching chain anchors SHALL pass verification.

### Resolver Identity Agent

- Agent SHALL expose:
  - `GET /v1/identity`
  - `GET /v1/upstreams`
  - `GET /v1/verification-chain`
  - `GET /healthz`
- Agent identity response SHALL bind resolver id, endpoint, upstream list, config version, health, issued time, expiry time, issuer/key id, and signature.
- Agent SHALL sign responses using Ed25519 when `RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64` is configured.
- Each Agent SHALL verify only its adjacent upstream recursive resolver through Indexer + chain Registry and SHALL sign the resulting `HopVerificationResult`.
- Each Agent SHALL aggregate downstream Agent results into a signed `VerificationChain`.
- Agent SHALL only read local resolver configuration and SHALL NOT modify DNS packets.

### Hop-by-hop distributed chain verification

- The wrapper SHALL directly verify only the first-hop resolver endpoint.
- The wrapper SHALL fetch the first-hop Agent `GET /v1/verification-chain` response after first-hop identity verification succeeds.
- The wrapper SHALL verify the first-hop Agent chain signature with the Agent public key bound in the verified first-hop resolver identity object.
- For each hop, the upstream resolver's Agent public key SHALL come from that hop's verified resolver evidence, not from local wrapper trust configuration.
- R1 Agent SHALL verify R2; R2 Agent SHALL verify R3; the chain SHALL terminate when an Agent declares configured terminal authoritative/external upstreams.
- Verification results SHALL bubble back from downstream Agents to upstream Agents and finally to the wrapper.
- The wrapper SHALL release DNS responses only when every signed hop has `accepted=true`, every downstream chain signature verifies, and `final_result=true` for the full chain.
- The wrapper SHALL fail closed on Agent signature failure, resolver id mismatch, endpoint mismatch, expired Agent response, Agent unavailable, loop detection, max depth exceeded, or incomplete downstream evidence.
- The wrapper SHALL NOT treat unobservable hidden middle resolvers as discovered.

### Cache

- Hot cache checks SHALL verify endpoint match, resolver id, object hash, version, status, soft TTL, hard TTL, object validity, and stored verification evidence.
- `VERIFIED` and `REFRESHING` cache entries MAY pass before hard TTL.
- Entries beyond hard TTL SHALL fail closed until full verification succeeds.
- Revocation, endpoint unbind, root revoke, resolver update, and Agent config-version changes SHALL invalidate relevant cache entries.
- In multi-process deployments, wrapper cache reads SHALL observe persistent cache status changes written by event-watcher.

### APIs

- Wrapper SHALL expose `/v1/verify/resolver`, `/v1/verify/query`, `/v1/cache`, `/v1/proofs/{request_id}`, `/healthz`, and `/metrics`.
- Indexer SHALL expose lookup, resolver, proof, status, and root routes.
- Admin SHALL expose resolver publish/revoke/root routes and a CLI.
- Agent legacy aliases `/v1/agent/identity` and `/v1/agent/observed-resolvers` MAY remain for compatibility.

## Non-functional requirements

- The implementation MUST fail closed for unknown, tampered, expired, revoked, endpoint-mismatched, stale-version, signature-invalid, root-invalid, Agent-invalid, or looped resolver chains.
- DNS protocol behavior MUST remain compatible with standard clients.
- Cold-path verification MAY contact Indexer, Agent, and chain registry; hot-path verification SHOULD remain local except first-hop Agent chain freshness checks.
- Tests MUST cover canonicalization, hash stability, signature failures, cache TTLs, registry state, Indexer tampering, UDP/TCP/DoH successful and failing queries, hop-by-hop Agent verification, Agent replay, Agent key mismatch, and revocation propagation.
