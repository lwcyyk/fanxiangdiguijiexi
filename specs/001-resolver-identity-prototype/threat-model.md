# Threat Model

## Trust boundaries

- DNS upstream resolver is not trusted until identity verification succeeds.
- Resolver Identity Agent is not trusted by itself; its response is trusted only after the resolver identity object has been verified and the Agent response verifies against the Ed25519 public key bound in that object. In distributed mode, each Agent is trusted only for its own adjacent-upstream `HopVerificationResult`; downstream chains must verify against public keys carried by prior verified hop evidence.
- SQLite Indexer is not trusted; it can be stale, compromised, or malicious.
- Chain registry is the trusted anchor for current object hash, endpoint binding, status, version, and root status.
- Local trusted cache is trusted only until hard TTL and only when bound to resolver id, endpoint, object hash, version, status, root, and verification evidence.

## Defended scenarios

- DHCP/RA/VPN/manual configuration injects malicious resolver IP.
- IP or endpoint impersonation.
- Indexer object tampering.
- Replayed old but correctly signed resolver object.
- Replayed or expired Agent response.
- Agent signed-hop tampering or downstream chain tampering.
- Agent public key mismatch.
- Endpoint unbind, resolver revocation, or root revocation.
- Agent unavailable in strict discovery mode.
- Recursive Agent chain loop or excessive depth.
- Off-path failure of Indexer/RPC while hot cache is still valid.

## Fail-closed cases

- Missing identity object.
- Missing endpoint binding.
- Chain anchor missing.
- Object hash mismatch.
- Resolver object signature verification failure.
- Root revoked or unknown.
- Status not `ACTIVE`.
- Object expired or not yet valid.
- Endpoint mismatch.
- Object version stale.
- Cache beyond hard TTL.
- Mandatory field unknown or unsupported.
- Missing Agent public key when Agent discovery is required.
- Agent signature invalid.
- Agent resolver id mismatch.
- Agent endpoint mismatch.
- Agent response expired or issued too far in the future.
- Agent chain loop or max depth exceeded.
- Downstream signed chain lacks a prior verified hop binding for its signer.

## Out of scope

- Proving the operator submitted truthful registration data.
- Preventing a legitimately registered malicious resolver from returning wrong answers.
- Authenticating authoritative DNS server behavior.
- Observing fully uncooperative hidden middle resolvers.
- Guessing resolvers that no authenticated Agent reports.
- Protecting against total compromise of chain admin keys or resolver Agent private keys.

## Mitigations

- Verify Indexer data against chain hash, endpoint binding, status, version, and root status.
- Verify resolver object signature.
- Bind Agent public key to verified resolver identity object.
- Verify Agent responses and hop/chain results with Ed25519 and short expiry.
- Detect Agent chain loops and enforce max depth.
- Bind cache entries to complete endpoint + resolver id + object hash + version + root + status + Agent key evidence.
- Use event watcher for revocation and hard TTL as backstop.
- Keep DNS wire format unchanged except verified failure `SERVFAIL`.
