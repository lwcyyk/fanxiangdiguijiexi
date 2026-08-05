//! Real-process startup regression test for the rustls CryptoProvider fix.
//!
//! RC1's wrapper never panicked (its only TLS is outbound via reqwest, which
//! resolves its own provider), but it now installs the same process-level
//! provider as the rest of the data plane for determinism. This test spawns the
//! actual `ri-wrapper` binary in production mode with test-only mTLS files and
//! asserts it stays up for at least 10 seconds, creates its TLS client config
//! (proven by the mTLS-required build succeeding before binding), serves UDP/TCP
//! DNS and monitoring, and never emits a panic.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

/// Always terminates the child, even when the test panics, so a failed run
/// cannot leave an orphaned wrapper holding the test ports.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TestPki {
    ca_cert: PathBuf,
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

        let mut client_params =
            CertificateParams::new(vec!["ri-test-client".to_string()]).expect("client params");
        client_params.is_ca = IsCa::NoCa;
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("client cert");

        let ca_cert = write(dir, "ca.crt", ca_cert.pem());
        let client_cert = write(dir, "client.crt", client_cert.pem());
        let client_key = write(dir, "client.key", client_key.serialize_pem());
        Self {
            ca_cert,
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

fn spawn_wrapper(dir: &Path, pki: &TestPki) -> Child {
    let private_key: [u8; 32] = [9u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
    let issuer_keys = format!(
        r#"{{"keys":[{{"issuer":"test-issuer","key_id":"issuer-key","algorithm":"ed25519","public_key":"{key_b64}"}}]}}"#
    );
    write(dir, "issuer-keys.json", issuer_keys);
    write(
        dir,
        "agent_token",
        "test-wrapper-agent-token-00000000000000000000".to_string(),
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ri-wrapper"));
    cmd.env("RI_ENVIRONMENT", "production")
        .env("RI_VERIFICATION_MODE", "controlled-strict")
        .env("RI_WRAPPER_AGENT_URL", "https://127.0.0.1:8443")
        .env("RI_WRAPPER_TLS_CLIENT_CERT_FILE", &pki.client_cert)
        .env("RI_WRAPPER_TLS_CLIENT_KEY_FILE", &pki.client_key)
        .env("RI_WRAPPER_TLS_CA_FILE", &pki.ca_cert)
        .env("RI_WRAPPER_UPSTREAMS", "udp://127.0.0.1:5353")
        .env("RI_WRAPPER_UDP_BIND", "127.0.0.1:25353")
        .env("RI_WRAPPER_TCP_BIND", "127.0.0.1:25354")
        .env("RI_WRAPPER_MONITORING_BIND", "127.0.0.1:29443")
        .env("RI_WRAPPER_AGENT_TOKEN_FILE", dir.join("agent_token"))
        .env("RI_ISSUER_KEYS_FILE", dir.join("issuer-keys.json"))
        .env("RI_DATABASE", dir.join("evidence.db"))
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().expect("spawn ri-wrapper")
}

fn read_child_output(child: &mut Child) -> String {
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

#[test]
fn wrapper_starts_and_serves_without_panicking() {
    ri_core::install_rustls_crypto_provider().expect("install provider in test process");

    let dir = tempfile::tempdir().expect("tempdir");
    let pki = TestPki::generate(dir.path());
    let mut child = ChildGuard(spawn_wrapper(dir.path(), &pki));
    let started = Instant::now();

    // The wrapper must run the full window. If it exits early, surface the
    // captured output (a TLS-config failure or the CryptoProvider regression
    // would appear here).
    let deadline = started + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            let output = read_child_output(&mut child.0);
            panic!("ri-wrapper exited before the 10s window: status={status:?}\noutput:\n{output}");
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    assert!(
        started.elapsed() >= Duration::from_secs(10),
        "wrapper must stay up for at least 10s (elapsed={:?})",
        started.elapsed()
    );
    assert!(
        child.0.try_wait().expect("try_wait").is_none(),
        "wrapper must still be running at the end of the window (no restart loop)"
    );

    child.0.kill().expect("kill wrapper");
    let output = read_child_output(&mut child.0);
    let _ = child.0.wait();

    // "listening" is logged only after Settings::from_env() and build_client()
    // succeeded (the TLS config was created), so its presence proves the mTLS
    // client config built without error or provider panic.
    assert!(
        output.contains("UDP DNS wrapper listening"),
        "wrapper must report UDP DNS listener: {output}"
    );
    assert!(
        output.contains("TCP DNS wrapper listening"),
        "wrapper must report TCP DNS listener: {output}"
    );
    assert!(
        output.contains("Wrapper monitoring listening"),
        "wrapper must report monitoring listener: {output}"
    );
    assert!(
        !output.contains("panicked") && !output.contains("CryptoProvider"),
        "wrapper output must not contain a panic:\n{output}"
    );
}
