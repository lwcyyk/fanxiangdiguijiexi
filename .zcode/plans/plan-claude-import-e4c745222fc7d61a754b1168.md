## Cache Provenance Fix

1. Replace the two positional Store cache-source lookups with one typed selector/result API.
   - Select by normalized `cache_object_digest`, current Registry generation, claimed `CLIENT_RESPONSE` lineage, and optional pinned `graph_digest`.
   - Do not compare the current cache-hit query digest with the source graph query digest.
   - Preserve source-internal binding by requiring the claimed source event's `query_digest` and `response_digest` to equal the source graph row's values.
   - Keep graph ownership through `claim.request_trace_id = graph.trace_id`; reject unclaimed events, wrong claim owners, wrong kinds, wrong object digests, wrong graph digests, and stale generations.

2. Update Trace Adapter enrichment.
   - Look up provenance using only the cache object selector and current generation.
   - Recompute the selected graph digest before placing it in `source_graph_digest`.
   - Keep the durable ACK/spool order and bounded provenance wait unchanged.
   - Continue uploading old cache hits without provenance after the wait so `controlled-strict` rejects them; do not introduce a sentinel or empty-error bypass.

3. Harden Agent source-graph consumption.
   - Pin the stored graph to the event's claimed `source_graph_digest` and recompute `object_hash`.
   - Fully run `EvidenceValidator` against the source graph's original challenge and issuance time, covering graph/identity/edge/attestation signatures and topology.
   - Recursively enforce current identity validity, DNS TTL expiry, nested cache provenance validity, DNSSEC compatibility, and current Registry generation.
   - Build, sign, validate, and persist the new cache-hit graph only after all source checks pass.
   - Preserve `controlled-strict`; legacy cache without verified provenance remains fail-close.

4. Strengthen the normalized DNS cache-object digest contract if existing parser APIs permit a focused change.
   - Require a DNS response with exactly one fully parsed question and no malformed/trailing wire data.
   - Add tests proving bindings to qname/qtype/qclass, rcode, RR data/order and EDNS, while retaining transaction-ID and ordinary-TTL invariance.

## Regression Coverage

5. Add focused Store tests for:
   - Different current/source query digests with the same cache object succeeding.
   - Wrong cache object, graph digest, generation, event kind, claim owner, and graph/event digest mismatch failing.

6. Add Trace Adapter tests for:
   - Cross-query cache provenance enrichment.
   - Persisting the enriched event in the durable spool.
   - Expired/missing source behavior and unchanged dead-letter/readiness semantics.

7. Extend Agent tests for:
   - Cross-query verified cache hits.
   - Altered graph JSON, altered signatures, expired identities, expired nested provenance, DNSSEC downgrade, and stale generation failing closed.
   - Original source challenge validation without consuming or reassigning trace claims.

8. Run:
   - `cargo fmt --all --check`.
   - Focused locked/offline tests for `ri-core`, `ri-store`, `ri-trace-adapter`, `ri-agent`, and `ri-knot-trace-producer`.
   - Full workspace locked/offline tests and clippy.
   - Existing Python deployment/configuration tests and shell/static checks.

## Build And Deployment

9. Produce the Rust 1.97 Bookworm release build, create the next deterministic OCI artifact, and verify archive/config/manifest digests before loading it on R1/R2/R3/Auth DNS.

10. Recreate only affected Rust services in downstream-first order while preserving volumes, Evidence DBs, Registry DBs, PKI, Norn state, caches, and evidence history.
    - Keep `RI_VERIFICATION_MODE=controlled-strict`.
    - Keep `RI_REGISTRY_MAX_STALENESS_SECONDS=45`.
    - Do not disable peer authentication, use `curl -k`, expose secrets, or run `docker compose down -v`.

## Acceptance

11. Re-run the complete positive path:
    - UDP/TCP A, AAAA, TXT through Wrapper.
    - DNSSEC `AD`/RRSIG through R1→R2→R3→Auth DNS.
    - Directional peer auth success plus invalid/cross-link 401/403.
    - At least 10 genuine cache misses, 10 provenance-verified hits, and explicit legacy-cache fail-close.
    - 20 sequential Wrapper requests and same-name/different-name concurrent requests.
    - Durable ACK/spool, Evidence Graph persistence/recomputation, claim isolation, and zero unexpected dead-letter growth.

12. Run all four required fail-close/recovery experiments with fresh names:
    - R1 Registry Sync stopped for more than 45 seconds.
    - R1 Agent stopped.
    - R1 Trace Producer stopped, including socket recreation/reconnect.
    - Invalid R1→R2 credential yielding downstream 401/403 and Wrapper SERVFAIL.
    - Restore the unchanged production configuration after each test and prove recovery before continuing.

13. Archive only secret-free evidence under `evidence/tencent-cloud/final-rc12-<UTC>/` (or the final successor build identifier), then produce one acceptance report with every required boolean.
    - Keep `production_capacity_validated=false` and `production_deployed=false`.
    - Unless unchanged trace-ID propagation is implemented and verified, keep `trace_binding_passed=false`, `trace_binding_known_p0=true`, and `release_ready=false`.