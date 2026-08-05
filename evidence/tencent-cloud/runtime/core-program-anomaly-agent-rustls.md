# Core program anomaly — ri-agent rustls CryptoProvider panic

Deployment evidence for the frozen-artifact defect. No private keys, no secrets — public digests only.

## Container (real deployment, ri-r3)

```
sudo docker logs ri-r3-agent-1 --tail 40
thread 'main' (1) panicked at .../rustls-0.23.42/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually, or make
sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.

sudo docker inspect ri-r3-agent-1 --format '{{.State.Status}} / restarts={{.RestartCount}} / exit={{.State.ExitCode}}'
restarting / restarts=19 / exit=101
```

Panic identical on every restart — deterministic, not OOM (exit 101 = Rust panic).

## Image identity (image-lock.json, ri-r3)

- archive: `rust.oci.tar` sha256 `34471fee2b260fa3d496a454298ef2881d27c4460b1991ee29ab19b5c4ca5b28`
- config digest: `sha256:3e4a31ccd54b799c67449342f9dd4225599cdc02bb18d81cf365f739456a366f`
- OCI manifest digest: `sha256:68ec104256119bd3cee736bc2ebb1f327370d31df3598606d7668ce84eda7244`
- local tag: `offline/resolver-identity/rust:ri-68ec104256119bd3`

Only two archives exist for the role (`knot.oci.tar`, `rust.oci.tar`); no alternative rust artifact.

## Source / build / dependency evidence (frozen commit 928ed0e)

- `rust/crates/ri-agent/src/main.rs:246` — `rustls::ServerConfig::builder()` (default-provider path); no `CryptoProvider::install_default()` anywhere in ri-agent or ri-wrapper.
- `docker/Dockerfile.rust` — `RUN cargo build --locked --release --workspace` (workspace feature unification).
- `rust/Cargo.toml` — `rustls = "0.23.40"` default features (aws_lc_rs); `tonic = { version = "0.13.1", features = ["tls-ring", ...] }`.
- `rust/Cargo.lock` — both `ring` and `aws-lc-rs` present in graph; `rustls 0.23.42`.

## Wizard blocker

```
安装工具 activate ...
错误代码：RUN002
原因：应用 readiness 超时：agent_trace_ready
建议：禁止标记安装完成；修复服务后重试，程序指针已回滚。
错误代码：E004
原因：安装执行失败：... activate ... returned non-zero exit status 2.
```

`agent_trace_ready` requires `https://<RI_FIELD_HOST_ID>:8443/readyz` from the agent; the frozen agent cannot start, so no resolver can be activated.

## Control-plane counterproof (what DOES work)

- r3 `registry-sync` container ran healthy and reconciled the signed registry snapshot from norn (mTLS) before the stack was stopped: `finalized Registry snapshot reconciled count=3`.
- r3 evidence DB (`/var/lib/resolver-identity/ri-r3/evidence-v2.db`) persisted — see `registry-sync-evidence.json`.
