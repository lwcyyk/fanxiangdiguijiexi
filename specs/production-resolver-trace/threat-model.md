# Production Resolver Trace threat model

## Assets

- per-query trace isolation and event ordering;
- exact upstream endpoint and DNS wire digest;
- last valid Registry snapshot and cache generation;
- Resolver, Agent, and Trace service credentials;
- the original DNS response held by Wrapper.

## Trust boundaries

Knot Resolver and its pinned hook are inside the resolver process boundary.
The Rust Producer is a separate non-root process on the same host. Unix peer
credentials and filesystem permissions protect both local sockets. Trace
Adapter is the durable ingestion boundary; Agent is the evidence validation
boundary; Registry Sync is the only chain access boundary.

## Threats and controls

| Threat | Control |
| --- | --- |
| qname/time-window cross-association | Random request context, exact digests, sequence, causal parent, single-use claim |
| repeated DNS transaction ID | Wrapper transaction pool plus resolver context identity; transaction ID is never the sole key |
| Trace modification or replay | immutable event IDs, exact event JSON conflict check, strict sequence, terminal state |
| dropped events under pressure | synchronous durable ACK; full spool returns an error and DNS fails closed |
| fake local producer | Unix peer UID check and mode-restricted directory |
| producer/adapter crash | hook acknowledgement timeout and SERVFAIL |
| endpoint substitution | endpoint comes from Knot's actual transport socket and is Registry-bound by Agent |
| stale cache proof | exact current-generation graph lookup and existing TTL/identity checks |
| direct chain access by data plane | network separation and no chain client/config in Producer, Agent, or Wrapper |
| malicious upstream response | exact attempt binding, DNS digest, endpoint identity, DNSSEC/Agent policy |
| sensitive DNS logging | only digests and endpoint metadata; no raw wire in logs or acceptance artifacts |
| supply-chain drift | Knot version, upstream commit, base images, and output images pinned and recorded |

## Residual risks

The Knot integration is a maintained patch against one exact upstream commit.
Upgrading Knot requires rebasing and repeating all acceptance cases. Local root
can replace processes or inspect DNS traffic and remains outside this
application-level protection. Public Anycast identity remains a service
identity, not proof of one physical machine.
