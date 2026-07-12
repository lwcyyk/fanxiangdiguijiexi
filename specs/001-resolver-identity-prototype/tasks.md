# Implementation Tasks

## Milestone 1 — Spec baseline

- [x] Create requirements/design/api/tasks/threat-model/experiments docs.
- [x] Add README with local prototype purpose and limits.
- [x] Update docs for Web3/Anvil, Docker Compose, hop-by-hop Agent verification, and Agent Ed25519 trust binding.

## Milestone 2 — Project bootstrap

- [x] Create `pyproject.toml`.
- [x] Create Python package directories.
- [x] Add shared config, errors, SQLite initialization.
- [x] Create Solidity Foundry layout.

## Milestone 3 — Identity object and crypto

- [x] Implement resolver identity models.
- [x] Implement canonical JSON excluding signature.
- [x] Implement object hash and lookup keys.
- [x] Implement prototype HMAC signing and verification.
- [x] Implement Ed25519 signing, verification, and key generation.
- [x] Bind Agent Ed25519 public key in resolver identity object attestation.
- [x] Add unit/integration tests and fixtures.

## Milestone 4 — Solidity registry

- [x] Implement `ResolverIdentityRegistryV1.sol`.
- [x] Add publish/update/revoke/bind/unbind/root methods.
- [x] Add events and authorization.
- [x] Add contract tests.

## Milestone 5 — SQLite Indexer and Admin

- [x] Implement schema and repositories.
- [x] Implement Indexer API.
- [x] Implement Admin object publish/revoke flow.
- [x] Add seed demo tool.

## Milestone 6 — Verifier and cache

- [x] Implement memory and SQLite trusted cache.
- [x] Implement full fail-closed resolver verification.
- [x] Preserve Agent public key evidence in cold and hot cache paths.
- [x] Implement proof journal and reasons.
- [x] Add hot/cold cache tests.

## Milestone 7 — DNS wrapper

- [x] Implement UDP DNS wrapper.
- [x] Implement TCP DNS wrapper.
- [x] Implement local DoH.
- [x] Implement fallback/SERVFAIL behavior.
- [x] Add protocol integration tests.

## Milestone 8 — Web3, revocation, and Agent

- [x] Implement Web3 registry backend.
- [x] Implement Anvil deployment/integration flow.
- [x] Implement event watcher cache invalidation.
- [x] Implement signed Resolver Identity Agent.
- [x] Implement Agent Ed25519 response verification against resolver object attestation.
- [x] Implement hop-by-hop distributed Agent resolver chain verification.
- [x] Add loop/max-depth/Agent failure tests.
- [x] Add multi-observed-resolver verification path.

## Milestone 9 — Docker Compose E2E

- [x] Implement Docker Compose multi-resolver testbed.
- [x] Dynamically deploy Anvil contract and inject Web3 config.
- [x] Use Web3RegistryBackend in wrapper/event-watcher path.
- [x] Verify UDP/TCP positive DNS flow.
- [x] Verify R1/R2 missing, Agent bad, Agent unavailable, chain revoke, root revoke, and config-version cache invalidation.

## Milestone 10 — Experiments and evaluation

- [x] Implement basic tampering, replay, malicious resolver, cold/hot cache, parallel verification, revocation, and OOB failure experiments.
- [ ] Upgrade experiments to emit thesis-ready latency tables for Web3/Compose E2E.
- [ ] Expand Prometheus-style metrics beyond liveness.
- [ ] Produce final evaluation report with screenshots/log excerpts if needed.

## Milestone 11 — Single-host production baseline

- [x] Add strict production configuration validation and secret-file loading.
- [x] Require Web3 Registry, pinned Ed25519 issuer keys, and distributed Agent verification.
- [x] Bind nested verification chains to a per-request Wrapper challenge.
- [x] Add persistent cache invalidation generations and Registry recheck before commit.
- [x] Persist Agent config high-water marks and EventWatcher cursor/hash.
- [x] Bind Registry endpoints to port/transport and full normalized endpoint material.
- [x] Add Admin authentication and Web3-backed Admin publishing.
- [x] Add metrics, readiness endpoint, bounded UDP inflight work, and bounded request journal.
- [x] Add hardened production image, Compose profile, CI, dependency lock, audit, and Runbook.
- [ ] Execute production acceptance against the operator-provided RPC, Registry contract, and resolver endpoints.
