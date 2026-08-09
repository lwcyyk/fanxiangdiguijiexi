# RC15 Cache Recovery Evidence

This directory records the RC15 ControlledStrict cache-provenance and recovery run on 2026-08-09 UTC.

Verified:

- one natural cache miss created canonical G0;
- three immediate cache hits referenced G0 directly;
- all 27 observed derived graphs referenced the same G0;
- Agent restart preserved immediate cached-query success;
- Registry Sync restart and reconciliation preserved cached-query success;
- 20 Agent down/up rounds returned SERVFAIL while down and NOERROR immediately after start, without clearing cache, waiting for TTL, or restarting the Resolver;
- `cache_object_digest` and `root_source_graph_digest` remained constant in all 20 rounds.

Additional recovery fix:

- restarting Trace Adapter makes the in-flight/first cached query fail closed; the patched RC15 Trace Producer then drops the stale Adapter stream and reconnects automatically on the next query. The second cached query succeeded without restarting Producer or Resolver, clearing cache, or waiting for TTL. The source also contains a Knot-hook optimization that keeps its Producer connection on an explicit `ERR`; its Resolver image rebuild remains pending because the pinned offline build inputs were not cached.

Historical dead-letter counters on R2/R3 predate this run and were not deleted. R1 finished with spool pending 0 and dead-letter total 0.

See `FINAL-RESULT.json`, `rounds.jsonl`, the per-round DNS transcripts, and `SHA256SUMS`.
