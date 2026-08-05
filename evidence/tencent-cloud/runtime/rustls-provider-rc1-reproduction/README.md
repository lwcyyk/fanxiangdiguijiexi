# RC1 rustls CryptoProvider panic — reproduction evidence

Reproduction of the frozen-artifact defect (source commit `928ed0e69fcf71149f4e224124b6a21e7c34aca0`,
release `0.3.0-norn-knot-rc1`). No private keys, no seeds, no production secrets — test-only material only.

## Method

1. Built the frozen workspace exactly as the frozen image does:
   `cargo build --locked --release --workspace` (see `docker/Dockerfile.rust`).
2. Started the original (pre-fix) binaries with test-only configuration and
   test-only certificates generated locally (`/tmp/ri-repro`):
   - X.509 v3 RSA test CA + server/client certs (webpki/reqwest reject v1 certs),
   - ephemeral test agent identity, test-only issuer-key file, distinct 32-byte+ test tokens.
3. Production mode (`RI_ENVIRONMENT=production`, `RI_VERIFICATION_MODE=controlled-strict`),
   all six mTLS files set, `RUST_BACKTRACE=1`, wrapped in `timeout 20`.

## Result — ri-agent

`evidence/tencent-cloud/runtime/rustls-provider-rc1-reproduction/rc1-repro-agent.out`

```
EXIT_CODE=101
thread 'main' (872053) panicked at .../rustls-0.23.42/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually, or make
sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
stack backtrace:
   0: __rustc::rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::option::expect_failed
   3: <rustls::webpki::client_verifier::WebPkiClientVerifier>::builder
   4: ri_agent::mtls_server_config
   5: ri_agent::main::{closure#0}
   6: <tokio::runtime::park::CachedParkThread>::block_on::<ri_agent::main::{closure#0}>
   7: ri_agent::main
```

- **exit code**: 101 (Rust panic)
- **panic location**: `rustls-0.23.42/src/crypto/mod.rs:249:14`
- **first rustls caller**: `WebPkiClientVerifier::builder` from `ri_agent::mtls_server_config`
  (`rust/crates/ri-agent/src/main.rs:246` → `rustls::ServerConfig::builder()`).
- Matches the real-deployment container panic exactly
  (see `evidence/tencent-cloud/runtime/core-program-anomaly-agent-rustls.md`, restarts=19 exit=101).

## Result — ri-wrapper

`evidence/tencent-cloud/runtime/rustls-provider-rc1-reproduction/rc1-repro-wrapper.out`

```
EXIT_CODE=124   (killed by `timeout 12` — the process ran for the full window)
INFO UDP DNS wrapper listening bind=127.0.0.1:15353
INFO TCP DNS wrapper listening bind=127.0.0.1:15354
INFO Wrapper monitoring listening bind=127.0.0.1:19443
```

- The wrapper **does not panic** on the CryptoProvider ambiguity.
- Root cause of the asymmetry: the wrapper's only TLS is outbound via reqwest
  (which resolves its own provider and does not take the process-default path),
  whereas the agent builds an **inbound** `rustls::ServerConfig` through the
  default-provider `builder()` — the path that panics.
- The wrapper is still wired into the fix (defensive, deterministic) so the whole
  data-plane stack installs the same provider at `main()` start.

## Dependency evidence (frozen Cargo.lock, rustls 0.23.42)

- `cargo-tree-features-reverse-rustls.txt` — both `ring` and `aws-lc-rs` feature edges into rustls.
- `cargo-tree-features-reverse-ring.txt` / `cargo-tree-features-reverse-aws-lc-rs.txt` — feature origins.
- `cargo-tree-features-ri-agent.txt` / `cargo-tree-features-ri-wrapper.txt` — full feature graph of the two binaries.

Both providers are feature-enabled in the single shared `rustls` crate, so the automatic
process-level provider selection deterministically panics (rustls 0.23 documented behavior).

## Interference note

The earlier failed run (before the X.509 v1 fix) surfaced `InvalidCertificate(UnsupportedCertVersion)`
from `reqwest::Certificate::from_pem` during `build_client`, which proves reqwest 0.13.4 builds and
validates its TLS config **eagerly** at `Client::builder().build()`. That error was a test-cert artifact
(v1 certificate), not the target anomaly, and is superseded by the panic capture above.
