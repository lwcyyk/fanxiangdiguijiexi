# Production Readiness Checklist

## Required before traffic

- [ ] External Registry contract address and chain ID independently verified.
- [ ] Registry runtime bytecode hash recorded in `.env.production` and independently compared with the deployment transaction.
- [ ] Separate admin, publisher, endpoint-manager, and revoker responsibilities documented.
- [ ] Production secrets generated, permission checked, encrypted backup completed.
- [ ] Issuer and Agent public keys verified out of band.
- [ ] HMAC disabled and distributed verification required.
- [ ] All recursive/forwarding hops have Agent connectivity or are explicitly documented terminal boundaries.
- [ ] Host firewall, RPC TLS, remote Agent TLS/mTLS, and log access controls configured.
- [ ] Plaintext Agent allowlist contains only same-host or private control-network service names.
- [ ] CI, Python tests, Foundry tests, coverage, lint, dependency audit, and Compose validation pass.
- [ ] Positive UDP/TCP DNS checks pass.
- [ ] Unknown resolver, signature tamper, Agent outage, resolver revoke, and root revoke return `SERVFAIL`.
- [ ] Metrics scraped and alerts installed for availability, rejection rate, latency, cache age, disk, and restart loops.
- [ ] Online backup passes `db_admin.py verify`; restore drill completed with the matching application image.
- [ ] Watcher `/readyz` dependency and `watcher:last_success_epoch` stale-heartbeat alert verified.
- [ ] Capacity test completed at expected peak QPS and chain depth.

## Explicit release blockers

- Default/example keys or RPC endpoints remain.
- Admin API is reachable beyond the management network.
- SQLite volume is shared across hosts or replicas.
- Any required Agent URL is missing or uses unauthenticated public HTTP.
- EventWatcher is unhealthy or behind the approved confirmation lag.
- Database schema version differs from the application-supported version.
- Registry runtime bytecode hash or chain ID differs from the pinned values.
- Negative-path smoke tests expose an original DNS answer.
