use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum_server::tls_rustls::RustlsConfig;
use ri_agent::{AgentConfig, AgentState, PeerCredentialsFile, router};
use ri_core::VerificationMode;
use ri_store::EvidenceStore;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ri_core::install_rustls_crypto_provider()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_agent=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    let store = EvidenceStore::open(&settings.database)?;
    let issuer_keys = AgentState::load_issuer_keys(&settings.issuer_keys_file)?;
    let client = build_client(&settings)?;
    let private_key = read_secret(&settings.private_key_file)?;
    ri_core::ed25519_public_key_b64(&private_key)?;
    let trace_ingest_token = read_secret(&settings.trace_ingest_token_file)?;
    let wrapper_api_token = read_secret(&settings.wrapper_api_token_file)?;
    let peer_credentials: PeerCredentialsFile =
        serde_json::from_str(&std::fs::read_to_string(&settings.peer_credentials_file)?)?;
    let (peer_inbound_credentials, peer_outbound_credentials, adjacent_peer_allowlist) =
        validate_peer_credentials(peer_credentials, &settings.server_id)?;
    let mut all_tokens = vec![trace_ingest_token.as_str(), wrapper_api_token.as_str()];
    all_tokens.extend(
        peer_inbound_credentials
            .iter()
            .map(|credential| credential.token.as_str()),
    );
    all_tokens.extend(peer_outbound_credentials.values().map(String::as_str));
    if all_tokens.iter().any(|token| token.len() < 32) {
        return Err("Agent API tokens must contain at least 32 bytes".into());
    }
    let mut unique_tokens = HashSet::new();
    if all_tokens
        .iter()
        .any(|token| !unique_tokens.insert(token.to_string()))
    {
        return Err("Agent API tokens must be distinct across purposes and peer directions".into());
    }
    let maintenance_store = store.clone();
    let trace_retention_seconds = settings.trace_retention_seconds;
    let graph_retention_seconds = settings.max_cache_ttl_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = unix_time();
            match maintenance_store.purge_trace_events(now.saturating_sub(trace_retention_seconds))
            {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "expired Trace events purged");
                }
                Err(error) => tracing::warn!(%error, "Trace retention maintenance failed"),
                _ => {}
            }
            if let Err(error) = maintenance_store.purge_query_contexts(now) {
                tracing::warn!(%error, "query context maintenance failed");
            }
            match maintenance_store.purge_expired(now.saturating_sub(graph_retention_seconds)) {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "expired evidence graphs purged");
                }
                Err(error) => tracing::warn!(%error, "graph retention maintenance failed"),
                _ => {}
            }
        }
    });
    let state = AgentState::new(
        AgentConfig {
            server_id: settings.server_id,
            private_key_b64: private_key,
            key_id: settings.key_id,
            mode: settings.mode,
            max_age_seconds: settings.max_age_seconds,
            trace_wait_millis: settings.trace_wait_millis,
            max_cache_ttl_seconds: settings.max_cache_ttl_seconds,
            registry_max_staleness_seconds: settings.registry_max_staleness_seconds,
            trace_ingest_token,
            wrapper_api_token,
            peer_inbound_credentials,
            peer_outbound_credentials,
            adjacent_peer_allowlist,
            max_concurrent_requests: settings.max_concurrent_requests,
            max_request_body_bytes: settings.max_request_body_bytes,
        },
        store,
        issuer_keys,
        client,
    );
    let app = router(state);
    if let (Some(cert), Some(key), Some(client_ca)) = (
        settings.tls_cert.as_deref(),
        settings.tls_key.as_deref(),
        settings.tls_client_ca.as_deref(),
    ) {
        let tls = mtls_server_config(cert, key, client_ca)?;
        axum_server::bind_rustls(settings.bind, tls)
            .serve(app.into_make_service())
            .await?;
    } else {
        if settings.production {
            return Err("production Agent requires server certificate, key, and client CA".into());
        }
        let listener = tokio::net::TcpListener::bind(settings.bind).await?;
        axum::serve(listener, app).await?;
    }
    Ok(())
}

struct Settings {
    production: bool,
    bind: SocketAddr,
    database: PathBuf,
    server_id: String,
    key_id: String,
    private_key_file: PathBuf,
    trace_ingest_token_file: PathBuf,
    wrapper_api_token_file: PathBuf,
    peer_credentials_file: PathBuf,
    issuer_keys_file: PathBuf,
    mode: VerificationMode,
    max_age_seconds: i64,
    trace_wait_millis: u64,
    max_cache_ttl_seconds: i64,
    registry_max_staleness_seconds: i64,
    trace_retention_seconds: i64,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    tls_client_cert: Option<PathBuf>,
    tls_client_key: Option<PathBuf>,
    tls_ca: Option<PathBuf>,
    http_timeout_millis: u64,
    max_concurrent_requests: usize,
    max_request_body_bytes: usize,
}

impl Settings {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let production = parse_environment(&required("RI_ENVIRONMENT")?)?;
        let mode = match required("RI_VERIFICATION_MODE")?.as_str() {
            "controlled-strict" => VerificationMode::ControlledStrict,
            "public-hybrid" => VerificationMode::PublicHybrid,
            _ => return Err("RI_VERIFICATION_MODE is invalid".into()),
        };
        let settings = Self {
            production,
            bind: required("RI_AGENT_BIND")?.parse()?,
            database: required("RI_DATABASE")?.into(),
            server_id: required("RI_AGENT_SERVER_ID")?,
            key_id: required("RI_AGENT_KEY_ID")?,
            private_key_file: required("RI_AGENT_PRIVATE_KEY_FILE")?.into(),
            trace_ingest_token_file: required("RI_TRACE_INGEST_TOKEN_FILE")?.into(),
            wrapper_api_token_file: required("RI_AGENT_WRAPPER_TOKEN_FILE")?.into(),
            peer_credentials_file: required("RI_AGENT_PEER_CREDENTIALS_FILE")?.into(),
            issuer_keys_file: required("RI_ISSUER_KEYS_FILE")?.into(),
            mode,
            max_age_seconds: parse_i64("RI_AGENT_MAX_AGE_SECONDS", 30)?,
            trace_wait_millis: parse_u64("RI_TRACE_WAIT_MILLIS", 250)?,
            max_cache_ttl_seconds: parse_i64("RI_MAX_CACHE_TTL_SECONDS", 3_600)?,
            registry_max_staleness_seconds: parse_i64("RI_REGISTRY_MAX_STALENESS_SECONDS", 15)?,
            trace_retention_seconds: parse_i64("RI_TRACE_RETENTION_SECONDS", 3_600)?,
            tls_cert: optional_path("RI_AGENT_TLS_CERT_FILE"),
            tls_key: optional_path("RI_AGENT_TLS_KEY_FILE"),
            tls_client_ca: optional_path("RI_AGENT_TLS_CLIENT_CA_FILE"),
            tls_client_cert: optional_path("RI_AGENT_TLS_CLIENT_CERT_FILE"),
            tls_client_key: optional_path("RI_AGENT_TLS_CLIENT_KEY_FILE"),
            tls_ca: optional_path("RI_AGENT_TLS_CA_FILE"),
            http_timeout_millis: parse_u64("RI_AGENT_HTTP_TIMEOUT_MS", 750)?,
            max_concurrent_requests: parse_usize("RI_AGENT_MAX_CONCURRENT_REQUESTS", 512)?,
            max_request_body_bytes: parse_usize(
                "RI_AGENT_MAX_REQUEST_BODY_BYTES",
                4 * 1_024 * 1_024,
            )?,
        };
        if !(1..=60).contains(&settings.max_age_seconds)
            || settings.trace_wait_millis == 0
            || settings.max_cache_ttl_seconds <= 0
            || settings.registry_max_staleness_seconds <= 0
            || settings.trace_retention_seconds < settings.max_age_seconds
            || settings.http_timeout_millis == 0
            || settings.max_concurrent_requests == 0
            || settings.max_request_body_bytes < 1_024
        {
            return Err("Agent time limits are outside the supported policy".into());
        }
        if settings.production
            && (settings.tls_cert.is_none()
                || settings.tls_key.is_none()
                || settings.tls_client_ca.is_none()
                || settings.tls_client_cert.is_none()
                || settings.tls_client_key.is_none()
                || settings.tls_ca.is_none())
        {
            return Err("production Agent requires server and outbound client mTLS files".into());
        }
        Ok(settings)
    }
}

fn build_client(settings: &Settings) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(settings.production)
        .timeout(std::time::Duration::from_millis(
            settings.http_timeout_millis,
        ));
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
        _ => return Err("Agent client certificate and key must be configured together".into()),
    }
    Ok(builder.build()?)
}

fn mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    let certs = load_certificates(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(client_ca_path)? {
        roots.add(certificate)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn load_certificates(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    Ok(CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    Ok(PrivateKeyDer::from_pem_file(path)?)
}

fn validate_peer_credentials(
    file: PeerCredentialsFile,
    local_server_id: &str,
) -> Result<
    (
        Vec<ri_agent::PeerInboundCredential>,
        HashMap<String, String>,
        HashSet<ri_agent::PeerPrincipal>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut inbound_principals = HashSet::new();
    let mut inbound_tokens = HashSet::new();
    for credential in &file.inbound {
        if credential.principal.server_id.is_empty()
            || credential.principal.key_id.is_empty()
            || credential.principal.server_id == local_server_id
            || credential.token.is_empty()
            || !inbound_principals.insert(credential.principal.clone())
            || !inbound_tokens.insert(credential.token.clone())
        {
            return Err("peer inbound credentials contain an invalid or duplicate entry".into());
        }
    }
    let mut outbound = HashMap::new();
    for credential in file.outbound {
        if credential.target_server_id.is_empty()
            || credential.target_server_id == local_server_id
            || credential.token.is_empty()
            || outbound
                .insert(credential.target_server_id, credential.token)
                .is_some()
        {
            return Err("peer outbound credentials contain an invalid or duplicate target".into());
        }
    }
    let allowlist = file
        .adjacent_peer_allowlist
        .into_iter()
        .collect::<HashSet<_>>();
    if allowlist.len() != file.inbound.len()
        || inbound_principals != allowlist
        || inbound_tokens.iter().any(|token| {
            outbound
                .values()
                .any(|outbound_token| outbound_token == token)
        })
    {
        return Err(
            "peer inbound credentials and adjacent allowlist must match exactly and use directional tokens"
                .into(),
        );
    }
    Ok((file.inbound, outbound, allowlist))
}

fn read_secret(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn parse_environment(value: &str) -> Result<bool, Box<dyn std::error::Error>> {
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

fn parse_i64(name: &str, default: i64) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}
