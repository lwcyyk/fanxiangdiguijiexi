# Security Boundary

## Trust premise

This system verifies recursive/forwarding resolver identity. Its security premise is:

> If a recursive/forwarding resolver identity is genuine, authorized, unexpired, endpoint-bound, and not revoked, the system assumes that resolver correctly executes DNS protocol behavior and returns the DNS response it intends to return.

The system does not prove that a legitimate resolver returns semantically correct DNS answers. It verifies whether the resolver chain is composed of authenticated, currently valid recursive/forwarding resolvers.

## Explicitly out of scope

The system does not study or defend against:

- compromise of a legitimately registered resolver;
- resolver misconfiguration;
- resolver cache poisoning after a resolver has been authenticated;
- malicious behavior by a legitimate resolver operator;
- DNSSEC validation or authoritative record signatures;
- authoritative DNS server authentication;
- root or TLD server authentication;
- TEE, TPM, remote attestation, or query execution proof;
- proof that a resolver actually forwarded a specific query exactly as claimed;
- automatic discovery of all hidden middle resolvers on the public Internet.

## Fail-closed policy

The system fails closed whenever identity evidence is missing, stale, tampered, expired, revoked, mismatched, or incomplete. The wrapper returns DNS `SERVFAIL` or an equivalent failed DNS response instead of releasing the original upstream answer.

Fail-closed conditions include:

- missing resolver identity object;
- missing or mismatched endpoint binding;
- missing chain anchor;
- object hash mismatch;
- invalid resolver object signature;
- inactive or revoked resolver status;
- inactive or revoked root status;
- invalid Merkle proof;
- endpoint not present in the resolver object;
- missing Agent public key when Agent evidence is required;
- invalid Agent signature;
- invalid hop signature;
- invalid downstream chain signature;
- hop evidence mismatch;
- Agent unavailable without valid signed evidence;
- Indexer or Registry unavailable without valid cache;
- replayed or expired hop/chain evidence;
- config version rollback;
- loop or max-depth violation;
- terminal authoritative/external endpoint represented as a verified resolver hop.

## Wrapper visibility limitation

The wrapper directly observes and authenticates only the configured first-hop resolver. It does not directly observe hidden downstream resolvers and it must not directly call R2/R3 Agents or directly query R2/R3 Indexer/Registry state in the distributed architecture.

Instead, downstream visibility is obtained through signed adjacent-hop evidence:

- R1 Agent verifies R2 and signs R1->R2 evidence.
- R2 Agent verifies R3 and signs R2->R3 evidence.
- Results return upstream until R1 sends the aggregate chain to Wrapper.

This means the wrapper's trust decision depends on verifying the signed evidence chain and ensuring each downstream signer was itself introduced by a previously verified hop.

## Security meaning of the stepwise Agent model

The stepwise model enforces locality of responsibility:

- each resolver operator exposes an Agent for local resolver state;
- each Agent can only speak authoritatively about its own local upstream configuration and adjacent-upstream verification result;
- no Agent can silently introduce a downstream chain unless a prior verified hop contains that downstream Agent's public key evidence;
- no terminal authoritative/external endpoint is treated as a recursive resolver identity unless it has a valid resolver identity object and appears as a legitimate recursive/forwarding hop.

The model reduces the wrapper's observational burden while preserving cryptographic accountability for each adjacent relationship.

## Boundary with normal DNS correctness

The DNS wire message is unchanged. The wrapper does not modify the query or the successful response. The system only gates response release based on resolver identity evidence. It does not validate DNS record truth, authoritative server behavior, or DNSSEC chains.
