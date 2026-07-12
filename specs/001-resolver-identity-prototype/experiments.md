# Experiments

## Functional closure

Demonstrate: DNS query -> upstream response -> pending verification -> resolver identity accepted -> original response returned.

## Malicious resolver injection

Configure wrapper upstream to an unregistered or endpoint-mismatched resolver. Expected result: fallback or `SERVFAIL`.

## Off-chain tampering

Modify Indexer SQLite object fields such as operator, endpoint, validity, object version, or resolver id. Expected result: object hash mismatch and rejection.

## Historical replay

Return an older signed object while chain anchor points to a newer version/hash. Expected result: stale version/hash mismatch rejection.

## Cold vs hot cache

Measure DNS end-to-end latency, verification latency, cache hit rate, Indexer request count, chain request count, P95/P99 for cold and hot paths.

## Parallel resolver verification

Configure Agent stub to return 1, 2, and 3 observed resolvers. Compare serial and parallel verification latency.

## Revocation propagation

Publish resolver, verify once, revoke on chain, observe event watcher invalidation, then run a new DNS query. Expected result: rejected response and cache marked revoked.

## Out-of-band failures

Simulate Indexer unavailable and chain RPC unavailable with:

1. valid hot cache before hard TTL — expected pass;
2. expired/no cache — expected fail closed.
