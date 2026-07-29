use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use ri_core::{IssuerKeyRegistry, VerificationMode};
use ri_store::EvidenceStore;
use ri_wrapper::{Metrics, WrapperConfig, WrapperState, make_servfail, parse_upstream};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_wrapper=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    let client = build_client(&settings)?;
    let issuer_keys = load_issuer_keys(&settings.issuer_keys_file)?;
    let registry_store = EvidenceStore::open(&settings.database)?;
    let agent_api_token = read_secret(&settings.agent_api_token_file)?;
    if agent_api_token.len() < 32 {
        return Err("Wrapper Agent API token must contain at least 32 bytes".into());
    }
    let state = Arc::new(WrapperState::new(
        WrapperConfig {
            mode: settings.mode,
            agent_url: settings.agent_url,
            agent_api_token,
            upstreams: settings.upstreams,
            upstream_timeout: settings.upstream_timeout,
            agent_timeout: settings.agent_timeout,
            transaction_id_reuse_delay: settings.transaction_id_reuse_delay,
            max_agent_response_bytes: settings.max_agent_response_bytes,
            max_inflight: settings.max_inflight,
            registry_max_staleness_seconds: settings.registry_max_staleness_seconds,
        },
        issuer_keys,
        client,
        registry_store,
    )?);

    let udp_state = Arc::clone(&state);
    let tcp_state = Arc::clone(&state);
    let metrics = state.metrics();
    let probe_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            probe_state.probe_agent().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let udp = tokio::spawn(serve_udp(settings.udp_bind, udp_state));
    let tcp = tokio::spawn(serve_tcp(
        settings.tcp_bind,
        tcp_state,
        settings.max_tcp_connections,
        settings.tcp_io_timeout,
    ));
    let monitoring = tokio::spawn(serve_monitoring(settings.monitoring_bind, metrics));
    tokio::select! {
        result = udp => result??,
        result = tcp => result??,
        result = monitoring => result??,
        _ = tokio::signal::ctrl_c() => {},
    }
    Ok(())
}

async fn serve_udp(bind: SocketAddr, state: Arc<WrapperState>) -> Result<(), AnyError> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!(%bind, "UDP DNS wrapper listening");
    loop {
        let mut query = vec![0_u8; ri_wrapper::MAX_DNS_MESSAGE_SIZE];
        let (size, peer) = socket.recv_from(&mut query).await?;
        query.truncate(size);
        let socket = Arc::clone(&socket);
        let state = Arc::clone(&state);
        let Some(permit) = state.try_acquire() else {
            state.record_overload();
            socket.send_to(&make_servfail(&query), peer).await?;
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let response = state.process_query(&query).await;
            if let Err(error) = socket.send_to(&response, peer).await {
                tracing::warn!(%peer, %error, "failed to send UDP DNS response");
            }
        });
    }
}

async fn serve_tcp(
    bind: SocketAddr,
    state: Arc<WrapperState>,
    max_connections: usize,
    io_timeout: Duration,
) -> Result<(), AnyError> {
    let listener = TcpListener::bind(bind).await?;
    let connections = Arc::new(Semaphore::new(max_connections));
    tracing::info!(%bind, "TCP DNS wrapper listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(connection) = Arc::clone(&connections).try_acquire_owned() else {
            tracing::warn!(%peer, "TCP DNS connection limit reached");
            drop(stream);
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _connection = connection;
            if let Err(error) = handle_tcp(stream, state, io_timeout).await {
                tracing::warn!(%peer, %error, "TCP DNS client failed");
            }
        });
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    state: Arc<WrapperState>,
    io_timeout: Duration,
) -> Result<(), AnyError> {
    loop {
        let length = match timeout(io_timeout, stream.read_u16()).await {
            Ok(Ok(length)) => length as usize,
            Err(_) => return Err("TCP DNS connection idle timeout".into()),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
        };
        if length < 12 {
            return Err("TCP DNS message is too short".into());
        }
        let mut query = vec![0_u8; length];
        timeout(io_timeout, stream.read_exact(&mut query))
            .await
            .map_err(|_| "TCP DNS frame read timeout")??;
        let Some(permit) = state.try_acquire() else {
            state.record_overload();
            let response = make_servfail(&query);
            write_tcp_response(&mut stream, &response, io_timeout).await?;
            continue;
        };
        let response = state.process_query(&query).await;
        drop(permit);
        write_tcp_response(&mut stream, &response, io_timeout).await?;
    }
}

async fn write_tcp_response(
    stream: &mut TcpStream,
    response: &[u8],
    io_timeout: Duration,
) -> Result<(), AnyError> {
    let length = u16::try_from(response.len()).map_err(|_| "TCP DNS response exceeds limit")?;
    timeout(io_timeout, async {
        stream.write_u16(length).await?;
        stream.write_all(response).await
    })
    .await
    .map_err(|_| "TCP DNS response write timeout")??;
    Ok(())
}

async fn serve_monitoring(bind: SocketAddr, metrics: Arc<Metrics>) -> Result<(), AnyError> {
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(readiness))
        .route("/metrics", get(render_metrics))
        .with_state(metrics);
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, "Wrapper monitoring listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn render_metrics(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics.render(),
    )
}

async fn readiness(State(metrics): State<Arc<Metrics>>) -> StatusCode {
    if metrics.is_ready() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

struct Settings {
    production: bool,
    udp_bind: SocketAddr,
    tcp_bind: SocketAddr,
    monitoring_bind: SocketAddr,
    mode: VerificationMode,
    agent_url: String,
    agent_api_token_file: PathBuf,
    upstreams: Vec<ri_wrapper::Upstream>,
    upstream_timeout: Duration,
    agent_timeout: Duration,
    transaction_id_reuse_delay: Duration,
    max_agent_response_bytes: usize,
    max_inflight: usize,
    registry_max_staleness_seconds: i64,
    max_tcp_connections: usize,
    tcp_io_timeout: Duration,
    issuer_keys_file: PathBuf,
    database: PathBuf,
    tls_client_cert: Option<PathBuf>,
    tls_client_key: Option<PathBuf>,
    tls_ca: Option<PathBuf>,
}

impl Settings {
    fn from_env() -> Result<Self, AnyError> {
        let production = parse_environment(&required("RI_ENVIRONMENT")?)?;
        let mode = match required("RI_VERIFICATION_MODE")?.as_str() {
            "controlled-strict" => VerificationMode::ControlledStrict,
            "public-hybrid" => VerificationMode::PublicHybrid,
            _ => return Err("RI_VERIFICATION_MODE is invalid".into()),
        };
        let agent_url = required("RI_WRAPPER_AGENT_URL")?;
        let tls_client_cert = optional_path("RI_WRAPPER_TLS_CLIENT_CERT_FILE");
        let tls_client_key = optional_path("RI_WRAPPER_TLS_CLIENT_KEY_FILE");
        let tls_ca = optional_path("RI_WRAPPER_TLS_CA_FILE");
        if production
            && (!agent_url.starts_with("https://")
                || tls_client_cert.is_none()
                || tls_client_key.is_none()
                || tls_ca.is_none())
        {
            return Err("production Wrapper requires HTTPS Agent URL and mTLS files".into());
        }
        let upstreams = required("RI_WRAPPER_UPSTREAMS")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(parse_upstream)
            .collect::<Result<Vec<_>, _>>()?;
        let max_tcp_connections = parse_usize("RI_WRAPPER_MAX_TCP_CONNECTIONS", 1_024)?;
        if max_tcp_connections == 0 {
            return Err("RI_WRAPPER_MAX_TCP_CONNECTIONS must be greater than zero".into());
        }
        let tcp_io_timeout = duration_ms("RI_WRAPPER_TCP_IO_TIMEOUT_MS", 5_000)?;
        if tcp_io_timeout.is_zero() {
            return Err("RI_WRAPPER_TCP_IO_TIMEOUT_MS must be greater than zero".into());
        }
        Ok(Self {
            production,
            udp_bind: required("RI_WRAPPER_UDP_BIND")?.parse()?,
            tcp_bind: required("RI_WRAPPER_TCP_BIND")?.parse()?,
            monitoring_bind: required("RI_WRAPPER_MONITORING_BIND")?.parse()?,
            mode,
            agent_url,
            agent_api_token_file: required("RI_WRAPPER_AGENT_TOKEN_FILE")?.into(),
            upstreams,
            upstream_timeout: duration_ms("RI_WRAPPER_UPSTREAM_TIMEOUT_MS", 2_000)?,
            agent_timeout: duration_ms("RI_WRAPPER_AGENT_TIMEOUT_MS", 1_000)?,
            transaction_id_reuse_delay: duration_ms(
                "RI_WRAPPER_TRANSACTION_ID_REUSE_DELAY_MS",
                15_000,
            )?,
            max_agent_response_bytes: parse_usize(
                "RI_WRAPPER_MAX_AGENT_RESPONSE_BYTES",
                4_194_304,
            )?,
            max_inflight: parse_usize("RI_WRAPPER_MAX_INFLIGHT", 512)?,
            registry_max_staleness_seconds: parse_i64("RI_REGISTRY_MAX_STALENESS_SECONDS", 15)?,
            max_tcp_connections,
            tcp_io_timeout,
            issuer_keys_file: required("RI_ISSUER_KEYS_FILE")?.into(),
            database: required("RI_DATABASE")?.into(),
            tls_client_cert,
            tls_client_key,
            tls_ca,
        })
    }
}

fn build_client(settings: &Settings) -> Result<reqwest::Client, AnyError> {
    let mut builder = reqwest::Client::builder()
        .https_only(settings.production)
        .timeout(settings.agent_timeout);
    if let Some(ca) = &settings.tls_ca {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    match (
        settings.tls_client_cert.as_deref(),
        settings.tls_client_key.as_deref(),
    ) {
        (Some(cert), Some(key)) => {
            let mut pem = std::fs::read(cert)?;
            pem.extend_from_slice(&std::fs::read(key)?);
            builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
        }
        (None, None) => {}
        _ => return Err("Wrapper TLS client certificate and key must be paired".into()),
    }
    Ok(builder.build()?)
}

#[derive(Deserialize)]
struct IssuerKeyFile {
    keys: Vec<IssuerKeyRecord>,
}

#[derive(Deserialize)]
struct IssuerKeyRecord {
    issuer: String,
    key_id: String,
    algorithm: String,
    public_key: String,
}

fn load_issuer_keys(path: &Path) -> Result<IssuerKeyRegistry, AnyError> {
    let file: IssuerKeyFile = serde_json::from_slice(&std::fs::read(path)?)?;
    if file.keys.is_empty() {
        return Err("issuer key bundle is empty".into());
    }
    let mut registry = IssuerKeyRegistry::default();
    let mut key_ids = std::collections::HashSet::new();
    for key in file.keys {
        if key.issuer.is_empty()
            || key.key_id.is_empty()
            || key.public_key.is_empty()
            || !key.algorithm.eq_ignore_ascii_case("ed25519")
        {
            return Err("issuer key record is invalid".into());
        }
        if !key_ids.insert((key.issuer.clone(), key.key_id.clone())) {
            return Err("issuer key bundle contains a duplicate issuer/key_id".into());
        }
        registry.insert(key.issuer, key.key_id, key.public_key);
    }
    Ok(registry)
}

fn required(name: &str) -> Result<String, AnyError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_secret(path: &Path) -> Result<String, AnyError> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

fn parse_environment(value: &str) -> Result<bool, AnyError> {
    match value {
        "production" => Ok(true),
        "development" | "test" => Ok(false),
        _ => Err("RI_ENVIRONMENT must be production, development, or test".into()),
    }
}

fn optional_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(Into::into)
}

fn parse_usize(name: &str, default: usize) -> Result<usize, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_i64(name: &str, default: i64) -> Result<i64, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn duration_ms(name: &str, default: u64) -> Result<Duration, AnyError> {
    Ok(Duration::from_millis(
        env::var(name).map_or(Ok(default), |value| value.parse())?,
    ))
}
