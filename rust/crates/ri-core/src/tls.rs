//! Deterministic rustls `CryptoProvider` installation.
//!
//! rustls 0.23 resolves the process-level [`CryptoProvider`] from crate features
//! when none has been installed, and **panics** when more than one provider
//! feature is enabled (see `CryptoProvider::get_default_or_install_from_crate_features`).
//! The resolver workspace enables both `ring` (via `tonic` `tls-ring` →
//! `tokio-rustls`) and `aws-lc-rs` (via rustls default features) in the same
//! `rustls` crate, so feature-based auto-selection is inherently ambiguous and
//! deterministically panics on every process that builds a rustls config
//! through the default-provider path (for example `ServerConfig::builder()`).
//!
//! Every data-plane binary must call [`install_rustls_crypto_provider()`] as the
//! first statement of `main()` to pin the provider explicitly. This never
//! panics, never `unwrap`s, and never falls back to feature auto-inference: a
//! conflict with a provider installed by another component is surfaced as an
//! error and the caller terminates.

use std::sync::OnceLock;

/// Install the process-level rustls `CryptoProvider` (ring) exactly once.
///
/// Uses [`rustls::crypto::ring::default_provider`] — ring is the provider the
/// data plane already selects through `tonic` `tls-ring`, and every TLS
/// consumer on the agent/wrapper/trace-adapter side (inbound rustls
/// `ServerConfig`, reqwest outbound `ClientConfig`, axum-server TLS, and the
/// `WebPkiClientVerifier`) is ring-compatible.
///
/// The first caller in a process performs the install; concurrent and repeated
/// callers observe the same result. If a conflicting provider was already
/// installed (or a second, different install is attempted later), an error is
/// returned instead of silently accepting a different provider. A subsequent
/// duplicate call to this function is not a conflict — it is idempotent.
pub fn install_rustls_crypto_provider() -> std::io::Result<()> {
    static PROVIDER: OnceLock<Result<(), String>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map(|_| ())
                .map_err(|_| {
                    "rustls CryptoProvider was already installed before \
                     install_rustls_crypto_provider() (ring); refusing a conflicting provider"
                        .to_string()
                })
        })
        .clone()
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::install_rustls_crypto_provider;

    /// cargo runs tests in a binary concurrently, and rustls's process-global
    /// provider must be installed before any config builder runs. Installing is
    /// idempotent (a `OnceLock`), so every test installs first to make the
    /// parallel-test ordering irrelevant.
    fn ensure_installed() {
        assert!(
            install_rustls_crypto_provider().is_ok(),
            "install_rustls_crypto_provider must succeed"
        );
    }

    #[test]
    fn provider_install_succeeds_once() {
        ensure_installed();
        // Installing is idempotent: repeated calls return the same success.
        let first = install_rustls_crypto_provider();
        assert!(first.is_ok(), "first install must succeed: {first:?}");
        let second = install_rustls_crypto_provider();
        assert!(
            second.is_ok(),
            "repeated install must be idempotent: {second:?}"
        );
    }

    #[test]
    fn provider_default_is_ring() {
        ensure_installed();
        let installed = rustls::crypto::CryptoProvider::get_default()
            .expect("install_rustls_crypto_provider must have set a process default");
        let ring_default = rustls::crypto::ring::default_provider();
        // Both reference the same static webpki algorithm table published by the
        // ring provider, so pointer equality distinguishes ring from aws-lc-rs.
        assert!(
            std::ptr::eq(
                installed.signature_verification_algorithms.all,
                ring_default.signature_verification_algorithms.all,
            ),
            "process-level default provider must be the ring provider"
        );
    }

    #[test]
    fn server_config_builder_no_panic() {
        ensure_installed();
        // The regression: with both ring and aws-lc-rs features enabled, these
        // default-provider builders used to panic at rustls crypto/mod.rs:249.
        // With the provider installed, building the configs must not panic.
        let _server_builder = rustls::ServerConfig::builder();
        let _client_builder = rustls::ClientConfig::builder();
    }
}
