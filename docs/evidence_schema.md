# Evidence Schema

## Overview

The stepwise Agent architecture uses two signed evidence objects:

- `HopVerificationResult`: one Agent's signed statement about one adjacent upstream resolver.
- `VerificationChain`: one Agent's signed summary of its own hop results plus downstream signed chains.

All signatures use Ed25519 over canonical JSON with `signature` fields removed before signing. Nested hop and downstream chain signatures remain covered by the parent chain signature as data fields, while each nested object is also independently verified with its own signer key.

## HopVerificationResult

A hop result represents `from_resolver -> adjacent_upstream`.

Core fields:

| Field | Security role |
|---|---|
| `schema_version` | Prevents accepting incompatible payloads. |
| `from_resolver_id` | Identifies the Agent/resolver producing this hop evidence. |
| `from_endpoint` | Binds the signer to the endpoint already verified for that resolver. |
| `upstream_endpoint` | Identifies the adjacent upstream endpoint being verified. |
| `upstream_resolver_id` | Resolver id that verification resolved for the upstream endpoint. |
| `accepted` | Boolean verification decision. |
| `status` | Verification status, for example `VERIFIED` or `REJECTED`. |
| `reasons` | Failure reasons when rejected. |
| `evidence` | Structured resolver verification evidence. |
| `issued_at` | Replay protection start time. |
| `expires_at` | Replay protection expiry time. |
| `issuer` | Agent issuer string. |
| `key_id` | Agent key id. |
| `signature` | Ed25519 signature by `from_resolver_id` Agent. |

Required evidence semantics for accepted recursive/forwarding resolver hops:

| Evidence field | Meaning |
|---|---|
| `from_resolver_id` | Must match hop `from_resolver_id`. |
| `upstream_resolver_id` | Must match hop `upstream_resolver_id`. |
| `upstream_endpoint` | Must match hop `upstream_endpoint`. |
| `upstream_type` | Normally `recursive_or_forwarder`; terminal boundary values are rejected for accepted resolver hops. |
| `verification_result` | Must match `VERIFIED` for accepted hops. |
| `object_hash` | Hash of the upstream resolver identity object checked against Registry. |
| `object_version` | Object version checked against Registry. |
| `resolver_status` | Must be `ACTIVE` for accepted hops. |
| `state_root` | Merkle root anchored in Registry. |
| `root_status` | Must be `ACTIVE` for accepted hops. |
| `endpoint_binding_status` | Must be `MATCHED` for accepted hops. |
| `endpoint_key` | Must match the canonical lookup key for `upstream_endpoint` when present. |
| `resolver_id_key` | Must match the hash key for `upstream_resolver_id` when present. |
| `issuer` | Hop evidence issuer. |
| `key_id` | Hop evidence key id. |
| `checked_at` | Time the adjacent Agent performed verification. |
| `expires_at` | Must match hop expiry. |
| `config_version` | Resolver or Agent configuration version associated with this verification. |
| `verifier_agent_id` | Must match `from_resolver_id`. |
| `agent_public_key` | Downstream Agent public key if the upstream resolver can produce a downstream chain. |
| `agent_key_algorithm` | Must be `ed25519` when `agent_public_key` is used. |
| `agent_key_id` | Downstream Agent key id. |

The wrapper validates evidence consistency after verifying the hop signature. It does not trust a bare `VERIFIED` string.

## VerificationChain

A chain result represents one Agent's signed summary.

| Field | Security role |
|---|---|
| `schema_version` | Prevents incompatible payload acceptance. |
| `resolver_id` | Resolver/Agent producing this chain. |
| `endpoint` | Endpoint of the chain signer. |
| `config_version` | Local Agent/resolver configuration version. |
| `hops` | Signed adjacent-hop verification results produced by this Agent. |
| `downstream_chains` | Signed chains returned by adjacent upstream Agents. |
| `terminal_upstreams` | Authoritative/external terminal boundaries, not resolver identity targets. |
| `chain_errors` | Errors encountered while building or validating downstream evidence. |
| `final_result` | Aggregate result for this Agent's local and downstream chain. |
| `issued_at` | Replay protection start time. |
| `expires_at` | Replay protection expiry time. |
| `issuer` | Agent issuer. |
| `key_id` | Agent key id. |
| `signature` | Ed25519 signature by this Agent. |

## Signature coverage

- `HopVerificationResult.signature` covers all hop fields except `signature`.
- `VerificationChain.signature` covers all chain fields except the chain's own `signature`.
- Parent chain signatures include nested hop/downstream-chain payloads as canonical JSON fields.
- The wrapper also independently verifies every nested hop and downstream chain signature using the correct Agent public key.

## Replay protection

Replay protection relies on:

- `issued_at` and `expires_at` in hop results;
- `issued_at` and `expires_at` in chain summaries;
- `config_version` monotonicity checks for cached first-hop chain context;
- hard TTLs in resolver trusted cache entries;
- Registry object versions and statuses.

Expired hop/chain evidence is rejected. A lower `config_version` for a previously observed chain signer is treated as rollback/replay and fails closed.

## Loop and max-depth protection

The wrapper keeps a visiting set of endpoint keys while validating nested chains. A chain is rejected when:

- a chain endpoint repeats in the current validation path;
- a hop points back to an endpoint already in the validation path;
- nested chain depth reaches `max_depth`;
- a downstream chain appears without a prior accepted hop carrying that downstream Agent's public key.

## Terminal boundary representation

Terminal authoritative/external upstreams are represented only in `VerificationChain.terminal_upstreams`. They are not represented as accepted `HopVerificationResult` resolver hops. Terminal values such as `terminal`, `authoritative_boundary`, or `external_boundary` in accepted hop evidence cause fail-closed rejection.

This preserves the boundary that root, TLD, and authoritative DNS servers are not part of recursive/forwarding resolver identity verification.
