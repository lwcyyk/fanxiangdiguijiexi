use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

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
            .push(DnType::CommonName, "ri-authority-test-ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut client_params =
            CertificateParams::new(vec!["ri-authority-test-client".into()]).expect("client params");
        client_params.is_ca = IsCa::NoCa;
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("client cert");

        Self {
            ca_cert: write_file(dir, "ca.crt", &ca_cert.pem()),
            client_cert: write_file(dir, "client.crt", &client_cert.pem()),
            client_key: write_file(dir, "client.key", &client_key.serialize_pem()),
        }
    }
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write test file");
    path
}

fn available_dns_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("bind candidate TCP port");
        let port = tcp.local_addr().expect("TCP local address").port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
    }
}

fn available_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind candidate port")
        .local_addr()
        .expect("candidate local address")
        .port()
}

fn read_output(child: &mut Child) -> String {
    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let mut error = String::new();
        let _ = stderr.read_to_string(&mut error);
        output.push_str(&error);
    }
    output
}

#[test]
fn authority_proxy_starts_with_production_mtls_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = TestPki::generate(dir.path());
    let token = write_file(
        dir.path(),
        "trace-token",
        "test-authority-trace-token-00000000000000000000\n",
    );
    let public_port = available_dns_port();
    let monitoring_port = available_tcp_port();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_ri-authority-proxy"))
            .env(
                "RI_AUTHORITY_PUBLIC_BIND",
                format!("127.0.0.1:{public_port}"),
            )
            .env(
                "RI_AUTHORITY_MONITORING_BIND",
                format!("127.0.0.1:{monitoring_port}"),
            )
            .env("RI_AUTHORITY_BACKEND", "127.0.0.1:1")
            .env("RI_AUTHORITY_SERVER_ID", "operator/authdns")
            .env("RI_AUTHORITY_AGENT_URL", "https://127.0.0.1:1")
            .env("RI_TRACE_INGEST_TOKEN_FILE", token)
            .env("RI_AUTHORITY_TLS_CLIENT_CERT_FILE", &pki.client_cert)
            .env("RI_AUTHORITY_TLS_CLIENT_KEY_FILE", &pki.client_key)
            .env("RI_AUTHORITY_TLS_CA_FILE", &pki.ca_cert)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn authority proxy"),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut health_response = None;
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().expect("check child") {
            let output = read_output(&mut child.0);
            panic!("authority proxy exited during startup: {status:?}\n{output}");
        }
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", monitoring_port)) {
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write health request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("read health response");
            health_response = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let health_response = health_response.expect("monitoring endpoint must start");
    assert!(health_response.starts_with("HTTP/1.1 204"));
    assert!(child.0.try_wait().expect("check running").is_none());

    child.0.kill().expect("kill authority proxy");
    let output = read_output(&mut child.0);
    let _ = child.0.wait();
    assert!(output.contains("authority UDP proxy listening"));
    assert!(output.contains("authority TCP proxy listening"));
    assert!(!output.contains("panicked") && !output.contains("CryptoProvider"));
}
