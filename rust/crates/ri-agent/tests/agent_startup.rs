//! Real-process startup regression test for the rustls CryptoProvider fix.
//!
//! RC1 (commit 928ed0e) panicked deterministically with exit code 101 at
//! `rustls-0.23.42/src/crypto/mod.rs:249` ("Could not automatically determine
//! the process-level CryptoProvider from Rustls crate features") because the
//! workspace enables both the `ring` and `aws-lc-rs` features in one `rustls`
//! crate and no process-level provider was installed. That panic prevented any
//! resolver agent from starting, so no wizard activation could succeed.
//!
//! This test spawns the *actual* `ri-agent` binary (the same artifact that runs
//! in the OCI image) in production mode with a test-only CA / server / client
//! certificate set, waits at least 10 seconds, and asserts:
//!   - the process is still running (it did not panic and exit 101),
//!   - the mTLS HTTPS listener answers `/healthz` (200, `ok: true`),
//!   - `/readyz` is reachable and correctly reports fail-close readiness gating,
//!   - no panic text appears in the captured output.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

/// Always terminates the child, even when the test panics, so a failed run
/// cannot leave an orphaned agent holding the test port.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Test-only PKI written to a temp directory. Never a production secret.
struct TestPki {
    ca_cert: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl TestPki {
    fn generate(dir: &Path) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "ri-test-ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("server params");
        server_params.is_ca = IsCa::NoCa;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "ri-test-server");
        let server_key = KeyPair::generate().expect("server key");
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert");

        let mut client_params =
            CertificateParams::new(vec!["ri-test-client".to_string()]).expect("client params");
        client_params.is_ca = IsCa::NoCa;
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("client cert");

        let ca_cert = write(dir, "ca.crt", ca_cert.pem());
        let server_cert = write(dir, "server.crt", server_cert.pem());
        let server_key = write(dir, "server.key", server_key.serialize_pem());
        let client_cert = write(dir, "client.crt", client_cert.pem());
        let client_key = write(dir, "client.key", client_key.serialize_pem());

        Self {
            ca_cert,
            server_cert,
            server_key,
            client_cert,
            client_key,
        }
    }
}

fn write(dir: &Path, name: &str, content: String) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write test file");
    path
}

/// Distinct, long-enough test tokens (≥32 bytes) and a fixed 32-byte test
/// identity private key. All test-only; no secrets.
fn write_secret_material() -> Vec<(&'static str, String)> {
    let mut files = Vec::new();
    for (name, token) in [
        (
            "trace_token",
            "test-trace-ingest-token-00000000000000000000",
        ),
        (
            "wrapper_token",
            "test-wrapper-api-token-00000000000000000000",
        ),
        (
            "peer_credentials.json",
            r#"{"inbound":[],"outbound":[],"adjacent_peer_allowlist":[]}"#,
        ),
    ] {
        files.push((name, token.to_string()));
    }
    let private_key: [u8; 32] = [7u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
    files.push(("agent_private_key", key_b64.clone()));
    let issuer_keys = format!(
        r#"{{"keys":[{{"issuer":"test-issuer","key_id":"issuer-key","algorithm":"ed25519","public_key":"{key_b64}"}}]}}"#
    );
    files.push(("issuer-keys.json", issuer_keys));
    files
}

fn spawn_agent(dir: &Path, pki: &TestPki) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ri-agent"));
    cmd.env("RI_ENVIRONMENT", "production")
        .env("RI_VERIFICATION_MODE", "controlled-strict")
        .env("RI_AGENT_BIND", "127.0.0.1:18443")
        .env("RI_DATABASE", dir.join("evidence.db"))
        .env("RI_AGENT_SERVER_ID", "ri-test")
        .env("RI_AGENT_KEY_ID", "ri-test-key")
        .env("RI_AGENT_PRIVATE_KEY_FILE", dir.join("agent_private_key"))
        .env("RI_TRACE_INGEST_TOKEN_FILE", dir.join("trace_token"))
        .env("RI_AGENT_WRAPPER_TOKEN_FILE", dir.join("wrapper_token"))
        .env(
            "RI_AGENT_PEER_CREDENTIALS_FILE",
            dir.join("peer_credentials.json"),
        )
        .env("RI_ISSUER_KEYS_FILE", dir.join("issuer-keys.json"))
        .env("RI_AGENT_TLS_CERT_FILE", &pki.server_cert)
        .env("RI_AGENT_TLS_KEY_FILE", &pki.server_key)
        .env("RI_AGENT_TLS_CLIENT_CA_FILE", &pki.ca_cert)
        .env("RI_AGENT_TLS_CLIENT_CERT_FILE", &pki.client_cert)
        .env("RI_AGENT_TLS_CLIENT_KEY_FILE", &pki.client_key)
        .env("RI_AGENT_TLS_CA_FILE", &pki.ca_cert)
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().expect("spawn ri-agent")
}

fn read_child_output(child: &mut Child) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let mut err = String::new();
        let _ = stderr.read_to_string(&mut err);
        out.push_str(&err);
    }
    out
}

#[tokio::test]
async fn agent_starts_and_serves_mtls_without_panicking() {
    ri_core::install_rustls_crypto_provider().expect("install provider in test process");

    let dir = tempfile::tempdir().expect("tempdir");
    let pki = TestPki::generate(dir.path());
    for (name, content) in write_secret_material() {
        write(dir.path(), name, content);
    }

    let mut child = ChildGuard(spawn_agent(dir.path(), &pki));
    let started = Instant::now();

    // mTLS probe client that trusts the test CA and presents the test client cert.
    let mut pem = std::fs::read(&pki.client_cert).expect("read client cert");
    pem.extend_from_slice(&std::fs::read(&pki.client_key).expect("read client key"));
    let identity = reqwest::Identity::from_pem(&pem).expect("client identity");
    let ca =
        reqwest::Certificate::from_pem(&std::fs::read(&pki.ca_cert).expect("read ca")).expect("ca");
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .identity(identity)
        .timeout(Duration::from_secs(2))
        .build()
        .expect("probe client");

    let mut healthz_body: Option<serde_json::Value> = None;
    let deadline = started + Duration::from_secs(15);
    while Instant::now() < deadline {
        // If the process died early (the RC1 regression panicked with 101),
        // report that immediately instead of waiting out the deadline.
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            let output = read_child_output(&mut child.0);
            panic!(
                "ri-agent exited before serving: status={status:?} (exit 101 = rustls \
                 CryptoProvider panic regression)\noutput:\n{output}"
            );
        }
        match client.get("https://127.0.0.1:18443/healthz").send().await {
            Ok(response) if response.status().is_success() => {
                healthz_body = Some(response.json().await.expect("healthz json"));
                break;
            }
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    let healthz_body = healthz_body.expect("healthz must be reachable over mTLS within 15s");

    // Stability window: the directive requires the process to keep running for
    // at least 10 seconds. Wait out the remainder of the window, watching for an
    // early exit (a restart-loop at the binary level is exactly the RC1 defect).
    while started.elapsed() < Duration::from_secs(10) {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            let output = read_child_output(&mut child.0);
            panic!(
                "ri-agent exited during the 10s stability window: status={status:?}\noutput:\n{output}"
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Still serving at the end of the window, and healthy.
    assert_eq!(
        healthz_body["ok"],
        serde_json::Value::Bool(true),
        "healthz ok at startup"
    );
    let again = client
        .get("https://127.0.0.1:18443/healthz")
        .send()
        .await
        .expect("healthz still reachable after 10s");
    assert_eq!(again.status(), reqwest::StatusCode::OK, "healthz after 10s");
    let again_body: serde_json::Value = again.json().await.expect("healthz json after 10s");
    assert_eq!(
        again_body["ok"],
        serde_json::Value::Bool(true),
        "healthz ok after 10s"
    );

    // readyz is reachable; without a fresh registry snapshot it must fail-close
    // (503, stale registry) rather than falsely report ready.
    let readyz = client
        .get("https://127.0.0.1:18443/readyz")
        .send()
        .await
        .expect("readyz reachable over mTLS");
    assert_eq!(
        readyz.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "readyz without a fresh registry snapshot must fail-close (503)"
    );

    // The process must still be running (no restart-loop at the binary level)
    // and must not have printed a panic.
    assert!(
        child.0.try_wait().expect("try_wait").is_none(),
        "agent must still be running after the probe window"
    );
    child.0.kill().expect("kill agent");
    let output = read_child_output(&mut child.0);
    assert!(
        !output.contains("panicked") && !output.contains("CryptoProvider"),
        "agent output must not contain a panic:\n{output}"
    );
    let _ = child.0.wait();
}
