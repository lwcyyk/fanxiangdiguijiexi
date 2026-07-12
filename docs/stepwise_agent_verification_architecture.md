# Stepwise Agent Verification Architecture

## Why the design changed

The local verification wrapper only directly connects to the first configured recursive or forwarding resolver. In a normal recursive DNS deployment it cannot directly observe every later recursive/forwarding hop. The previous prototype mode, where the wrapper recursively called every Agent and directly verified every downstream resolver, was useful for early testing but did not match that deployment boundary.

The current architecture therefore uses stepwise identity discovery and verification:

```text
Wrapper -> R1
R1 Agent -> verifies adjacent R2
R2 Agent -> verifies adjacent R3 or reaches terminal authoritative/external upstream
R3/R2 results -> R1 -> Wrapper
```

Each resolver-side Agent reads only its local resolver configuration, verifies only its adjacent upstream recursive/forwarding resolver, signs that hop result, and returns the signed result to the previous hop. The wrapper receives a signed `VerificationChain` from R1 and validates the chain evidence instead of directly connecting to R2/R3 Agents.

## Responsibility boundaries

### Wrapper

- Directly verifies only the first-hop resolver endpoint R1.
- Extracts R1 Agent Ed25519 public key from the verified R1 identity object.
- Calls only R1 Agent's `/v1/verification-chain` in the distributed architecture.
- Verifies R1 chain signature, every signed hop, downstream chain signatures, adjacency, loop/max-depth, replay window, final result, and evidence integrity.
- Releases the DNS response only when the signed observable recursive/forwarding chain verifies.
- Does not directly connect to R2/R3 Agents.
- Does not directly query R2/R3 Indexer or Registry state.
- Does not authenticate root, TLD, or authoritative DNS servers.

### Resolver Identity Agent

- Runs beside a controlled recursive/forwarding resolver.
- Reads local upstream configuration for that resolver.
- Verifies only adjacent upstream recursive/forwarding resolvers.
- Queries an Indexer and the chain Registry for adjacent upstream identity material.
- Signs its own `HopVerificationResult` and `VerificationChain` with its Ed25519 Agent key.
- Calls only adjacent upstream Agents when a configured adjacent upstream is itself a controlled recursive/forwarding resolver.
- Marks configured authoritative/external upstreams as terminal boundaries instead of resolver identity targets.

### Indexer

- Stores full resolver identity objects, lookup indexes, Merkle proofs, state roots, trusted cache rows, and audit logs.
- Is not a trust oracle.
- Can be stale, unavailable, or malicious.
- Its data is trusted only after the verifier checks chain anchor, object hash, endpoint binding, object signature, object version, resolver status, proof, and root status.

### Registry

- Is the trusted on-chain anchor for current resolver object hash, resolver version, status, endpoint binding, and root status.
- In the local prototype this can be SQLite-backed or Web3/Anvil-backed; the Docker Compose E2E path uses Web3/Anvil.

## Detailed R1 -> R2 -> R3 flow

1. Wrapper forwards the DNS query to configured first-hop R1 and keeps the DNS response pending.
2. Wrapper verifies R1 through normal resolver verification.
3. R1 verification evidence includes R1 Agent public key from `attestation.agent`.
4. Wrapper sends a fresh random challenge with `POST /v1/verification-chain` to R1 Agent. The GET form remains diagnostic-only.
5. R1 Agent reads its local upstream configuration and discovers adjacent upstream R2.
6. R1 Agent queries Indexer and Registry for R2 identity material.
7. R1 Agent verifies R2 object hash, Merkle proof, chain anchor, endpoint binding, status, version, validity, and signature.
8. R1 Agent emits and signs `HopVerificationResult(R1 -> R2)`.
9. If R2 has an Agent URL configured, R1 Agent calls R2 Agent.
10. R2 Agent repeats the same adjacent-only process for R3.
11. If R2's upstream is configured as authoritative/external terminal, R2 records it under `terminal_upstreams` and does not run resolver identity verification on it.
12. R2 signs the shared Wrapper challenge in its `VerificationChain` and returns it to R1.
13. R1 verifies the downstream challenge, embeds R2's signed downstream chain, signs the same challenge in its own chain summary, and returns it to Wrapper.
14. Wrapper verifies signatures and evidence consistency from R1 down through the signed chain.
15. Wrapper releases the original DNS response only when the full observable recursive/forwarding chain verifies.

## Terminal boundaries

`terminal_upstreams`, `authoritative_boundary`, and `external_boundary` represent the point where controlled recursive/forwarding resolver verification stops. They mean: the next upstream is not treated as a recursive/forwarding resolver identity target in this prototype.

A terminal boundary:

- may appear in `VerificationChain.terminal_upstreams`;
- must not appear as an accepted resolver `HopVerificationResult`;
- is not looked up in resolver identity Indexer/Registry;
- is not considered a failed resolver verification simply because it has no resolver identity object.

If a terminal authoritative/external endpoint is disguised as a verified resolver hop, wrapper evidence validation fails closed.

## Why root, TLD, and authoritative DNS are not authenticated

The prototype studies recursive/forwarding resolver identity, not authoritative DNS data authenticity. Root, TLD, and authoritative servers belong to the normal DNS resolution path and are out of scope for resolver identity verification. Authenticating authoritative records would require different mechanisms such as DNSSEC, which is explicitly outside this prototype.

## Why Indexer is not an Oracle

The Indexer does not decide trust. It only provides material:

- resolver object JSON;
- endpoint lookup rows;
- Merkle proof material;
- local root metadata;
- cache/audit rows.

The verifier checks that material against the chain Registry and object signatures. A malicious Indexer cannot make a resolver pass unless the chain anchor, endpoint binding, object hash, object signature, status, and proof/root checks are consistent.

## Why each resolver does not need a local full Indexer

A resolver-side Agent only needs to query an Indexer service for its adjacent upstream's identity material. It does not need to store the entire identity database locally. The Indexer is read-only from the Agent's perspective and can be independently operated, replicated, or cached. Trust still comes from the chain Registry and signatures, not from local possession of the full Indexer dataset.

## Why Agents query independent Indexer and chain Registry

Each Agent is responsible for verifying its adjacent upstream. To do so it needs:

- chain state for the upstream resolver id and endpoint binding;
- Indexer object/proof data for that upstream;
- the upstream resolver object's Agent key evidence if a downstream Agent chain is expected.

This preserves the stepwise responsibility boundary: R1 verifies R2, R2 verifies R3, and the wrapper verifies signed evidence rather than performing all downstream lookups itself.
