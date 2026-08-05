# RC2 image host validation — findings (Task #13)

Date: 2026-08-05 (UTC)
Host: ri-r3 (118.195.189.105, 10.206.16.7)

## Result (final): RESOLVED — RC2 image passes docker-load + container smoke test

The glibc mismatch below was resolved by rebuilding the five RC2 binaries inside
the official `rust:1.97.0-bookworm` builder (glibc 2.36) and re-running the OCI
assembly. The final RC2 archive digests are recorded in
`evidence/tencent-cloud/oci/rc2/oci-verification.json` and
`oci-digest-record.json`.

Original finding follows (kept for the audit trail):

## Result (initial): BLOCKED — glibc baseline mismatch in assembled RC2 image

The RC2 binaries were compiled on the local build host (Ubuntu, glibc 2.39),
but the RC2 image reuses the frozen RC1 base layers, whose runtime is
debian bookworm-slim (glibc 2.36). The newly built binaries require
`GLIBC_2.38`, so the RC2 agent cannot start on the RC1 base.

This was caught by the docker-load + container smoke test step of Task #13
host validation, not by any local check.

## Evidence

### docker load (OK)
```
Loaded image: resolver-identity/rust-data-plane:0.3.0-norn-knot-rc2
resolver-identity/rust-data-plane:0.3.0-norn-knot-rc2 b843071ae390
resolver-identity/rust-data-plane:0.3.0-norn-knot-rc1 68ec10425611
```
Image ID `b843071ae390` == RC2 manifest digest prefix (sha256:b843071ae390...) —
Docker 29 OCI-layout semantics confirmed. RC1 image (68ec10425611) still present,
untouched.

### Container start + probe
Container created and started; mTLS healthz probe on `https://agent:8443/healthz`
never succeeded. Container logs:

```
/usr/local/bin/ri-agent: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /usr/local/bin/ri-agent)
```

Exit: dynamic loader failure before main() — deterministic, not the rustls panic.

### Binary glibc symbol baselines
| binary | max GLIBC symbol required | runs on bookworm (2.36)? |
|--------|---------------------------|--------------------------|
| RC1 ri-agent (frozen release asset) | GLIBC_2.34 | yes |
| RC2 ri-agent (local build, glibc 2.39 host) | GLIBC_2.38 | no |

## Resolution path

Rebuild the five RC2 data-plane binaries inside the official builder image
`rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073`
(bookworm, glibc 2.36) — the same builder `docker/Dockerfile.rust` uses — then
re-run `deploy/tencent-cloud/scripts/build-rust-data-plane-oci.py` with the
rebuilt binaries and re-run this smoke test. The RC1 archive remains byte-for-byte
frozen; only the RC2 binaries layer and dependent digests change.

## Files
- Smoke container: `rc2-smoke-agent` (stopped/removed after capture)
- RC1 archive sha256 (unchanged): 34471fee2b260fa3d496a454298ef2881d27c4460b1991ee29ab19b5c4ca5b28
