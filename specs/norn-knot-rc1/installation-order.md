# Installation order

1. Install `ri-hub-mgmt-01` and verify offline identity/snapshot tooling.
2. Install Node A, generate its unique node key and mTLS material, then wait for genesis.
3. Record Node A's peer ID; install Node B as an independent read replica without `-g`.
4. Verify both read-only proxies reject every method except the three approved read RPCs.
5. Pin the observed genesis in Inventory and re-render resolver configuration.
6. Generate and publish the signed snapshot through the authenticated SSH publication tunnel.
7. Install resolver Registry Sync instances on `resolver-L01-r1, resolver-L01-r2, resolver-L01-r3` and verify independent SQLite files.
8. Install Agent and Trace Adapter on every resolver host.
9. Install Wrapper only on the `first-hop` host.

Do not cut DNS traffic until the release manifest records a script-generated,
successful production Resolver Trace acceptance result.
