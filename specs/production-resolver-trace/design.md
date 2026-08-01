# Production Resolver Trace design

## Runtime path

```text
client
  -> Wrapper (first-hop only)
  -> Knot Resolver 6.3.0
  -> pinned worker lifecycle hook
  -> ri-knot-trace-producer
  -> Trace Adapter durable spool
  -> Agent
  -> local trusted SQLite
```

The hook is deliberately small. It exports exact request, send, receive,
failure, and finish facts from Knot's `request_ctx` and `qr_task` lifecycle.
It sends a length-bounded binary frame over a mode-restricted Unix socket and
waits for a bounded acknowledgement.

The Rust producer owns request state. Its key is `(kresd pid, request uid)`;
the externally visible `trace_id` is 128 random bits and is never derived from
qname, time, or DNS transaction ID. Each context maintains:

- immutable client query digest and correlation ID;
- the next event sequence;
- all unresolved outbound attempts;
- last transport and endpoint;
- whether any upstream send occurred;
- terminal state.

An outbound response is accepted only for an unresolved attempt in the same
context with the same endpoint and DNS transaction ID. The full normalized
query digest and response digest are then recorded. Reuse of an event or
terminal context is rejected.

## Trace event state machine

```text
CLIENT_QUERY (sequence 1)
  -> UPSTREAM_QUERY
     -> UPSTREAM_RESPONSE
     |  -> UPSTREAM_RETRY
     |  -> TRANSPORT_SWITCH
     |  -> UPSTREAM_TIMEOUT
  -> CACHE_HIT
  -> CLIENT_RESPONSE | RESOLUTION_FAILED
```

Every event after sequence 1 refers to an existing earlier event in the same
trace. A response refers to its exact outbound query event. Adapter ingestion
atomically validates and advances the per-trace sequence before acknowledging.
Malformed or out-of-order events never enter the durable upload queue.

## Cache provenance

The resolver correctly reports a cache-only execution but does not read the
evidence database. On CacheHit ingestion, Trace Adapter resolves the query
digest and a canonical cache-object digest against the current Registry
generation in the local evidence database, then attaches the exact existing
graph digest. The cache digest clears the DNS transaction ID and
resource-record TTL fields, but still binds flags, names, types, classes and
RDATA. Missing, expired or generation-mismatched provenance is quarantined and
makes readiness fail. This is a cryptographic object lookup, not a
query-association time window.

## Agent association

Wrapper registration uses the transaction ID rewritten from its exclusive
pool, exact correlation ID, query digest, response digest, and a database row
boundary. Downstream Agent requests use the exact correlation and DNS digests,
plus single-use event claiming. No request contains or evaluates an
`expected_observed_at` association window.

Graph edges are built only from a successfully paired
`UPSTREAM_QUERY`/`UPSTREAM_RESPONSE`. Timeout and switch events are retained as
auditable failure-path evidence but do not become successful identity edges.

## Packaging

The field inventory pins five image digests: management, Rust data plane,
Go-Norn, Nginx read proxy, and the patched Knot Resolver. The resolver-link
Compose file runs the resolver and Trace Producer on both roles, and exposes
Wrapper only through the `first-hop` profile.

The package stores resolver integration state below
`/opt/resolver-identity/state/resolver-config`. Lifecycle scripts never compile
on a field host and never delete state implicitly.
