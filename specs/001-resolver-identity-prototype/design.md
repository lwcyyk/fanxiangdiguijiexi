# Design — Resolver Identity Prototype

## Architecture

```text
DNS client
  | UDP/TCP/DoH
  v
Local DNS Verification Wrapper
  | normal DNS forwarding, unmodified DNS wire message
  v
R1 recursive resolver -> R2 recursive resolver -> authoritative/external DNS
  | DNS response
  v
Wrapper pending gate
  | out-of-band identity path
  +--> ResolverVerifier: verify first-hop R1 only
  +--> R1 Agent /v1/verification-chain
        R1 Agent verifies R2 via Indexer + Registry
        R2 Agent verifies R3 via Indexer + Registry
        signed results bubble back R3 -> R2 -> R1 -> wrapper
  v
accept original response OR SERVFAIL
```

The normal DNS path and the identity path are separate. The identity path never modifies DNS packets. The wrapper directly authenticates only the first-hop resolver; each Resolver Identity Agent authenticates only its adjacent upstream resolver and returns signed evidence upward.

## Main components

- `wrapper`: UDP/TCP DNS listeners, local DoH, upstream forwarding, pending response gate, proof journal, first-hop verification, signed Agent chain validation, SERVFAIL generation.
- `verifier`: fail-closed resolver identity verification, policy checks, memory/SQLite trusted cache.
- `indexer`: FastAPI service over SQLite storing full identity objects, lookup indexes, proofs, roots, and audit logs. It is untrusted until checked against chain anchors.
- `admin`: object builder, publisher CLI/API, hash/sign/store/publish workflow.
- `chain`: SQLite prototype registry, Web3 registry backend, contract loader, event watcher.
- `contracts`: `ResolverIdentityRegistryV1` Solidity anchor registry.
- `agent`: config-driven Resolver Identity Agent exposing signed local resolver identity/upstream state.

## Verification sequence

1. Normalize the observed first-hop endpoint from wrapper upstream config.
2. Wrapper calls `ResolverVerifier.verify_endpoint(first_hop)`.
3. Verifier checks endpoint binding, chain anchor, object hash, object version, object signature, Merkle proof, root status, validity, status, and endpoint semantics.
4. Verifier stores trusted evidence including `attestation.agent` metadata: `agent_public_key`, `agent_key_algorithm`, and `agent_key_id`.
5. Wrapper fetches R1 Agent `/v1/verification-chain` and verifies the chain summary using the R1 Agent public key from R1's verified object.
6. R1 Agent verifies only adjacent R2 by calling its local `ResolverVerifier` over Indexer + Registry, signs `HopVerificationResult(R1 -> R2)`, and attaches any R2 downstream chain.
7. R2 Agent repeats the same adjacent-only process for R3, and so on, until an Agent reaches configured terminal authoritative/external upstreams.
8. Wrapper validates every nested chain signature using Agent public keys carried in the previous verified hop evidence.
9. Loop detection and `max_depth` prevent cyclic or unbounded chain evidence.
10. QueryCoordinator forwards the DNS query normally, keeps the response pending, and releases it only if the first-hop verification and signed distributed verification chain both pass.

## Hop-by-hop Agent chain evidence

The recursive authentication responsibility is distributed:

- wrapper authenticates R1;
- R1 Agent authenticates R2;
- R2 Agent authenticates R3;
- downstream signed results bubble back to the wrapper through R1.

Each `HopVerificationResult` binds:

- `from_resolver_id` and `from_endpoint`;
- `upstream_endpoint` and verified `upstream_resolver_id`;
- accepted/status/reasons/evidence from normal resolver verification;
- issued/expiry window and Ed25519 signature.

Each `VerificationChain` binds:

- Agent resolver id, endpoint, config version;
- signed hop results;
- signed downstream chains;
- terminal authoritative/external upstreams;
- chain errors and final result;
- issued/expiry window and Ed25519 signature.

The wrapper does not recursively query every downstream Indexer/Registry itself in the distributed mode. It verifies cryptographic evidence produced by the responsible adjacent upstream Agent.

## Agent trust binding

Resolver objects bind Agent public keys in `attestation.agent`:

```json
{
  "agent": {
    "algorithm": "ed25519",
    "public_key": "<base64 raw public key>",
    "key_id": "agent-key-01"
  }
}
```

The Agent signs this payload shape:

```json
{
  "schema_version": "resolver-identity-agent-v1",
  "resolver_id": "operator-a/r1",
  "endpoint": {"ip": "172.30.0.11", "port": 1053, "transport": "udp"},
  "upstreams": [{"ip": "172.30.0.12", "port": 1053, "transport": "udp"}],
  "config_version": "1",
  "health": "ok",
  "issued_at": 0,
  "expires_at": 0,
  "issuer": "resolver-agent",
  "key_id": "agent-key-01",
  "signature": "base64:ed25519:..."
}
```

A signed Agent response is trusted only after the resolver identity object has been verified and supplies the matching Agent public key.

## Cache state machine

```text
UNKNOWN -> VERIFIED -> REFRESHING -> VERIFIED
VERIFIED -> EXPIRED
VERIFIED -> REVOKED
any -> REJECTED
```

Allowed states: `VERIFIED`, and `REFRESHING` before hard TTL. Hard TTL cannot exceed the resolver object's `valid_until`.

Hot cache rows retain evidence needed for Agent trust binding, including Agent public key metadata. In multi-process Compose deployments, the wrapper reads persistent cache status before trusting in-memory rows so event-watcher revocations are observed.

## SQLite schema

- `resolver_objects`: full JSON object, object hash, version, status, validity, issuer, key id.
- `resolver_endpoints`: normalized endpoint records.
- `resolver_lookup_index`: lookup key to resolver id key mapping.
- `resolver_proofs`: Merkle proof material.
- `state_roots`: local root metadata.
- `audit_logs`: append-only admin/indexer/wrapper events.
- `trusted_cache`: local verified evidence for hot-path checks.
- `registry_anchors`, `registry_endpoint_bindings`, `registry_roots`: local prototype registry storage mirroring contract state.

## Contract storage

`ResolverIdentityRegistryV1` stores:

- `mapping(bytes32 => bytes32) endpointToResolverIdKey`
- `mapping(bytes32 => ResolverAnchor) resolverAnchors`
- `mapping(bytes32 => RootRecord) rootRecords`

`ResolverAnchor` contains resolver id key, object hash, state root, object version, valid until, and status.

## Failure handling

- Unknown resolver: fail closed.
- Missing endpoint binding: fail closed.
- Indexer unavailable + valid hot cache: allow until hard TTL if chain/Agent requirements for the query path are still satisfied.
- Indexer unavailable + no/expired cache: fail closed.
- Chain unavailable + valid hot cache: allow until hard TTL only when the cached evidence remains valid.
- Chain unavailable + no/expired cache: fail closed.
- Signature/hash/root/status/endpoint mismatch: fail closed.
- Agent unavailable, Agent replay, Agent public key missing/mismatch, resolver id mismatch, loop, or max depth exceeded: fail closed.
- Wrapper response: verified original response on success; DNS `SERVFAIL` on failure.
