use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use ri_authority_proxy::{
    AuthorityProxyConfig, AuthorityProxyState, DnsTransport, Metrics, make_servfail,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ri_core::install_rustls_crypto_provider()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_authority_proxy=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    let client = build_client(&settings)?;
    let state = Arc::new(AuthorityProxyState::new(
        AuthorityProxyConfig {
            server_id: settings.server_id,
            public_ip: settings.public_bind.ip(),
            public_port: settings.public_bind.port(),
            backend: settings.backend,
            agent_url: settings.agent_url,
            trace_ingest_token: read_secret(&settings.trace_ingest_token_file)?,
            backend_timeout: settings.backend_timeout,
            agent_timeout: settings.agent_timeout,
            max_agent_response_bytes: settings.max_agent_response_bytes,
        },
        client,
    )?);
    let probe_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            probe_state.probe_agent().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let monitoring = tokio::spawn(serve_monitoring(settings.monitoring_bind, state.metrics()));
    let udp = tokio::spawn(serve_udp(
        settings.public_bind,
        Arc::clone(&state),
        settings.max_udp_queries,
    ));
    let tcp = tokio::spawn(serve_tcp(
        settings.public_bind,
        state,
        settings.max_tcp_connections,
        settings.io_timeout,
    ));
    tokio::select! {
        result = monitoring => result??,
        result = udp => result??,
        result = tcp => result??,
        _ = tokio::signal::ctrl_c() => {},
    }
    Ok(())
}

async fn serve_udp(
    bind: SocketAddr,
    state: Arc<AuthorityProxyState>,
    max_queries: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let queries = Arc::new(Semaphore::new(max_queries));
    tracing::info!(%bind, "authority UDP proxy listening");
    loop {
        let mut query = vec![0_u8; ri_authority_proxy::MAX_DNS_MESSAGE_SIZE];
        let (size, peer) = socket.recv_from(&mut query).await?;
        query.truncate(size);
        let Ok(permit) = Arc::clone(&queries).try_acquire_owned() else {
            let response = make_servfail(&query);
            if let Err(error) = socket.send_to(&response, peer).await {
                tracing::warn!(%peer, %error, "failed to send overloaded authority UDP response");
            }
            continue;
        };
        let socket = Arc::clone(&socket);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let response = state.process_query(&query, DnsTransport::Udp).await;
            if let Err(error) = socket.send_to(&response, peer).await {
                tracing::warn!(%peer, %error, "failed to send authority UDP response");
            }
        });
    }
}

async fn serve_tcp(
    bind: SocketAddr,
    state: Arc<AuthorityProxyState>,
    max_connections: usize,
    io_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind).await?;
    let connections = Arc::new(Semaphore::new(max_connections));
    tracing::info!(%bind, "authority TCP proxy listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            tracing::warn!(%peer, "authority TCP connection limit reached");
            drop(stream);
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_tcp(stream, state, io_timeout).await {
                tracing::warn!(%peer, %error, "authority TCP client failed");
            }
        });
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    state: Arc<AuthorityProxyState>,
    io_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let length = match timeout(io_timeout, stream.read_u16()).await {
            Ok(Ok(length)) => usize::from(length),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err("authority TCP idle timeout".into()),
        };
        if !(12..=ri_authority_proxy::MAX_DNS_MESSAGE_SIZE).contains(&length) {
            return Err("authority TCP frame length is invalid".into());
        }
        let mut query = vec![0_u8; length];
        timeout(io_timeout, stream.read_exact(&mut query))
            .await
            .map_err(|_| "authority TCP read timeout")??;
        let response = state.process_query(&query, DnsTransport::Tcp).await;
        let response_length =
            u16::try_from(response.len()).map_err(|_| "authority response exceeds TCP limit")?;
        timeout(io_timeout, async {
            stream.write_u16(response_length).await?;
            stream.write_all(&response).await
        })
        .await
        .map_err(|_| "authority TCP write timeout")??;
    }
}

async fn serve_monitoring(
    bind: SocketAddr,
    metrics: Arc<Metrics>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(readiness))
        .route("/metrics", get(render_metrics))
        .with_state(metrics);
    let listener = TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn readiness(State(metrics): State<Arc<Metrics>>) -> StatusCode {
    if metrics.is_ready() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn render_metrics(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics.render(),
    )
}

struct Settings {
    public_bind: SocketAddr,
    monitoring_bind: SocketAddr,
    backend: SocketAddr,
    server_id: String,
    agent_url: String,
    trace_ingest_token_file: PathBuf,
    tls_client_cert: PathBuf,
    tls_client_key: PathBuf,
    tls_ca: PathBuf,
    backend_timeout: Duration,
    agent_timeout: Duration,
    io_timeout: Duration,
    max_agent_response_bytes: usize,
    max_udp_queries: usize,
    max_tcp_connections: usize,
}

impl Settings {
    fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let settings = Self {
            public_bind: required("RI_AUTHORITY_PUBLIC_BIND")?.parse()?,
            monitoring_bind: required("RI_AUTHORITY_MONITORING_BIND")?.parse()?,
            backend: required("RI_AUTHORITY_BACKEND")?.parse()?,
            server_id: required("RI_AUTHORITY_SERVER_ID")?,
            agent_url: required("RI_AUTHORITY_AGENT_URL")?,
            trace_ingest_token_file: required("RI_TRACE_INGEST_TOKEN_FILE")?.into(),
            tls_client_cert: required("RI_AUTHORITY_TLS_CLIENT_CERT_FILE")?.into(),
            tls_client_key: required("RI_AUTHORITY_TLS_CLIENT_KEY_FILE")?.into(),
            tls_ca: required("RI_AUTHORITY_TLS_CA_FILE")?.into(),
            backend_timeout: Duration::from_millis(parse_u64(
                "RI_AUTHORITY_BACKEND_TIMEOUT_MS",
                750,
            )?),
            agent_timeout: Duration::from_millis(parse_u64("RI_AUTHORITY_AGENT_TIMEOUT_MS", 750)?),
            io_timeout: Duration::from_millis(parse_u64("RI_AUTHORITY_IO_TIMEOUT_MS", 2_000)?),
            max_agent_response_bytes: parse_usize(
                "RI_AUTHORITY_MAX_AGENT_RESPONSE_BYTES",
                1_048_576,
            )?,
            max_udp_queries: parse_usize("RI_AUTHORITY_MAX_UDP_QUERIES", 4_096)?,
            max_tcp_connections: parse_usize("RI_AUTHORITY_MAX_TCP_CONNECTIONS", 1_024)?,
        };
        if !settings.agent_url.starts_with("https://")
            || settings.backend_timeout.is_zero()
            || settings.agent_timeout.is_zero()
            || settings.io_timeout.is_zero()
            || settings.max_agent_response_bytes < 1_024
            || settings.max_udp_queries == 0
            || settings.max_tcp_connections == 0
        {
            return Err("authority proxy environment is invalid".into());
        }
        Ok(settings)
    }
}

fn build_client(
    settings: &Settings,
) -> Result<reqwest::Client, Box<dyn std::error::Error + Send + Sync>> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(&settings.tls_ca)?)?;
    let mut identity = std::fs::read(&settings.tls_client_cert)?;
    if !identity.ends_with(b"\n") {
        identity.push(b'\n');
    }
    identity.extend_from_slice(&std::fs::read(&settings.tls_client_key)?);
    Ok(reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(settings.agent_timeout)
        .add_root_certificate(ca)
        .identity(reqwest::Identity::from_pem(&identity)?)
        .build()?)
}

fn read_secret(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn parse_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_usize(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}
