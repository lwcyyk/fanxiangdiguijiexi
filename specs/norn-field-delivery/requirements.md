# Go-Norn field delivery requirements

## Goal

Produce three non-secret, checksummed installation packages from one pinned Git
commit:

1. center management and publication;
2. one reusable Go-Norn node package for `node-a` and `node-b`;
3. one resolver-link package for `first-hop` and `upstream`.

The phase is a packaging and multi-server simulation exercise. It does not
connect to production servers, change DNS routes, merge the base PR or add a
new blockchain adapter.

## Required outputs

- `resolver-identity-management-<version>.tar.gz`
- `resolver-identity-norn-node-<version>.tar.gz`
- `resolver-identity-resolver-link-<version>.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`
- `installation-order.md`
- `network-matrix.json`
- `secret-requirements.json`
- one non-secret config directory per inventory host

## Failure conditions

Rendering or installation must fail when:

- an image is not pinned by a complete digest or uses `latest`;
- Node A and B share a host, data directory, key profile or TLS profile;
- resolver units share Server IDs, Agent key IDs, data directories, Trace
  sockets, secret profiles or TLS profiles;
- a resolver points to fewer than two HTTPS Norn read endpoints;
- an upstream unit configures or starts Wrapper;
- a package contains a private key, token, certificate private material,
  database, WAL file or credential-bearing URL;
- package checksums, source commit or Registry pins do not match.

## Production boundary

The repository does not contain a production resolver-internal Trace producer.
All releases must set `production_trace_ready=false`. This is a P0 DNS cutover
blocker and cannot be replaced by test fixtures, packet capture or time-window
correlation.
