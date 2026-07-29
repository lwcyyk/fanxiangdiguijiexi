use std::env;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use ri_core::TraceEventV2;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

const MAX_LINE_BYTES: usize = 65_536;
type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_trace_adapter=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    prepare_socket(&settings.socket)?;
    let listener = UnixListener::bind(&settings.socket)?;
    std::fs::set_permissions(
        &settings.socket,
        std::fs::Permissions::from_mode(settings.socket_mode),
    )?;
    let client = build_client(&settings)?;
    let spool = TraceSpool::open(&settings.spool_database, settings.max_spool_events)?;
    let token = std::fs::read_to_string(&settings.token_file)?
        .trim()
        .to_owned();
    if token.len() < 32 {
        return Err("trace ingestion token must contain at least 32 bytes".into());
    }
    let (sender, receiver) = mpsc::channel(settings.queue_capacity);
    let mut worker = tokio::spawn(upload_worker(
        receiver,
        spool.clone(),
        client,
        settings.agent_url,
        token,
        settings.batch_size,
        settings.flush_interval,
    ));
    let mut monitoring = tokio::spawn(serve_monitoring(settings.monitoring_bind, spool.clone()));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tracing::info!(
        socket = %settings.socket.display(),
        expected_uid = settings.expected_uid,
        "trace adapter listening"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if stream.peer_cred()?.uid() != settings.expected_uid {
                    tracing::warn!(uid = stream.peer_cred()?.uid(), "rejected trace producer");
                    continue;
                }
                let sender = sender.clone();
                let spool = spool.clone();
                tokio::spawn(async move {
                    if let Err(error) = read_events(stream, sender, spool).await {
                        tracing::warn!(%error, "trace producer connection failed");
                    }
                });
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                return Ok(());
            }
            _ = terminate.recv() => {
                return Ok(());
            }
            result = &mut worker => {
                result??;
                return Ok(());
            }
            result = &mut monitoring => {
                result??;
                return Ok(());
            }
        }
    }
}

async fn read_events(
    stream: UnixStream,
    sender: mpsc::Sender<()>,
    spool: TraceSpool,
) -> Result<(), AnyError> {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::with_capacity(4096);
    loop {
        line.clear();
        let size = reader.read_until(b'\n', &mut line).await?;
        if size == 0 {
            return Ok(());
        }
        if size > MAX_LINE_BYTES {
            return Err("trace event line exceeds maximum size".into());
        }
        while line
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let event = serde_json::from_slice::<TraceEventV2>(&line)?;
        let write_spool = spool.clone();
        tokio::task::spawn_blocking(move || write_spool.enqueue(&event)).await??;
        sender
            .send(())
            .await
            .map_err(|_| "trace upload worker stopped")?;
    }
}

async fn upload_worker(
    mut receiver: mpsc::Receiver<()>,
    spool: TraceSpool,
    client: reqwest::Client,
    agent_url: String,
    token: String,
    batch_size: usize,
    flush_interval: Duration,
) -> Result<(), AnyError> {
    let endpoint = format!("{}/v2/trace-events/batch", agent_url.trim_end_matches('/'));
    loop {
        let mut batch = load_batch_async(&spool, batch_size).await?;
        if batch.is_empty() {
            receiver.recv().await.ok_or("trace event channel closed")?;
            let deadline = tokio::time::Instant::now() + flush_interval;
            while batch.len() < batch_size {
                match tokio::time::timeout_at(deadline, receiver.recv()).await {
                    Ok(Some(())) => {
                        batch = load_batch_async(&spool, batch_size).await?;
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            if batch.is_empty() {
                batch = load_batch_async(&spool, batch_size).await?;
            }
        }
        process_batch(&client, &endpoint, &token, &spool, &batch).await?;
        while receiver.try_recv().is_ok() {}
    }
}

async fn process_batch(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    spool: &TraceSpool,
    batch: &[TraceEventV2],
) -> Result<(), AnyError> {
    match upload_batch(client, endpoint, token, batch).await? {
        UploadDisposition::Uploaded => acknowledge_async(spool, batch.to_vec()).await,
        UploadDisposition::PayloadRejected { status } if batch.len() == 1 => {
            quarantine_async(spool, batch[0].clone(), status).await
        }
        UploadDisposition::PayloadRejected { status } => {
            tracing::warn!(
                %status,
                count = batch.len(),
                "isolating rejected Trace batch"
            );
            for event in batch {
                match upload_batch(client, endpoint, token, std::slice::from_ref(event)).await? {
                    UploadDisposition::Uploaded => {
                        acknowledge_async(spool, vec![event.clone()]).await?;
                    }
                    UploadDisposition::PayloadRejected { status } => {
                        quarantine_async(spool, event.clone(), status).await?;
                    }
                }
            }
            Ok(())
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum UploadDisposition {
    Uploaded,
    PayloadRejected { status: u16 },
}

async fn upload_batch(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    batch: &[TraceEventV2],
) -> Result<UploadDisposition, AnyError> {
    let mut delay = Duration::from_millis(20);
    let mut attempt = 0_u64;
    loop {
        attempt = attempt.saturating_add(1);
        let response = client
            .post(endpoint)
            .bearer_auth(token)
            .json(batch)
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                return Ok(UploadDisposition::Uploaded);
            }
            Ok(response) => {
                let status = response.status();
                if matches!(status.as_u16(), 400 | 409 | 413 | 422) {
                    return Ok(UploadDisposition::PayloadRejected {
                        status: status.as_u16(),
                    });
                }
                if !(status.is_server_error() || matches!(status.as_u16(), 408 | 425 | 429)) {
                    return Err(format!(
                        "Agent trace endpoint returned non-retryable status {status}"
                    )
                    .into());
                }
                tracing::warn!(attempt, %status, "Agent temporarily rejected trace batch");
            }
            Err(error) => {
                tracing::warn!(attempt, %error, "trace batch upload failed");
            }
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(Duration::from_secs(5));
    }
}

async fn load_batch_async(spool: &TraceSpool, limit: usize) -> Result<Vec<TraceEventV2>, AnyError> {
    let spool = spool.clone();
    tokio::task::spawn_blocking(move || spool.load_batch(limit)).await?
}

async fn acknowledge_async(spool: &TraceSpool, events: Vec<TraceEventV2>) -> Result<(), AnyError> {
    let spool = spool.clone();
    tokio::task::spawn_blocking(move || spool.acknowledge(&events)).await??;
    Ok(())
}

async fn quarantine_async(
    spool: &TraceSpool,
    event: TraceEventV2,
    status: u16,
) -> Result<(), AnyError> {
    let event_id = event.event_id.clone();
    let spool = spool.clone();
    tokio::task::spawn_blocking(move || {
        spool.quarantine(
            &event,
            &format!("Agent rejected payload with HTTP {status}"),
        )
    })
    .await??;
    tracing::error!(%event_id, status, "Trace event moved to dead letter");
    Ok(())
}

struct Settings {
    production: bool,
    socket: PathBuf,
    socket_mode: u32,
    expected_uid: u32,
    spool_database: PathBuf,
    queue_capacity: usize,
    batch_size: usize,
    flush_interval: Duration,
    agent_url: String,
    token_file: PathBuf,
    tls_client_cert: Option<PathBuf>,
    tls_client_key: Option<PathBuf>,
    tls_ca: Option<PathBuf>,
    http_timeout: Duration,
    monitoring_bind: SocketAddr,
    max_spool_events: usize,
}

impl Settings {
    fn from_env() -> Result<Self, AnyError> {
        let production = parse_environment(&required("RI_ENVIRONMENT")?)?;
        let agent_url = required("RI_TRACE_AGENT_URL")?;
        let tls_client_cert = optional_path("RI_TRACE_TLS_CLIENT_CERT_FILE");
        let tls_client_key = optional_path("RI_TRACE_TLS_CLIENT_KEY_FILE");
        let tls_ca = optional_path("RI_TRACE_TLS_CA_FILE");
        if production
            && (!agent_url.starts_with("https://")
                || tls_client_cert.is_none()
                || tls_client_key.is_none()
                || tls_ca.is_none())
        {
            return Err("production trace adapter requires Agent mTLS configuration".into());
        }
        let batch_size = parse_usize("RI_TRACE_BATCH_SIZE", 64)?;
        if !(1..=1_024).contains(&batch_size) {
            return Err("RI_TRACE_BATCH_SIZE must be between 1 and 1024".into());
        }
        let queue_capacity = parse_usize("RI_TRACE_QUEUE_CAPACITY", 8_192)?;
        if queue_capacity == 0 {
            return Err("RI_TRACE_QUEUE_CAPACITY must be positive".into());
        }
        let max_spool_events = parse_usize("RI_TRACE_SPOOL_MAX_EVENTS", 1_000_000)?;
        if max_spool_events == 0 {
            return Err("RI_TRACE_SPOOL_MAX_EVENTS must be positive".into());
        }
        Ok(Self {
            production,
            socket: required("RI_TRACE_SOCKET")?.into(),
            socket_mode: u32::from_str_radix(
                &env::var("RI_TRACE_SOCKET_MODE").unwrap_or_else(|_| "600".into()),
                8,
            )?,
            expected_uid: required("RI_TRACE_PRODUCER_UID")?.parse()?,
            spool_database: env::var("RI_TRACE_SPOOL_DATABASE")
                .unwrap_or_else(|_| "/var/lib/resolver-identity/trace-spool.db".into())
                .into(),
            queue_capacity,
            batch_size,
            flush_interval: Duration::from_millis(parse_u64("RI_TRACE_FLUSH_INTERVAL_MS", 5)?),
            agent_url,
            token_file: required("RI_TRACE_INGEST_TOKEN_FILE")?.into(),
            tls_client_cert,
            tls_client_key,
            tls_ca,
            http_timeout: Duration::from_millis(parse_u64("RI_TRACE_HTTP_TIMEOUT_MS", 500)?),
            monitoring_bind: env::var("RI_TRACE_MONITORING_BIND")
                .unwrap_or_else(|_| "127.0.0.1:9110".into())
                .parse()?,
            max_spool_events,
        })
    }
}

#[derive(Clone)]
struct TraceSpool {
    connection: Arc<Mutex<Connection>>,
    max_events: usize,
}

impl TraceSpool {
    fn open(path: &Path, max_events: usize) -> Result<Self, AnyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS trace_spool (
              event_id TEXT PRIMARY KEY,
              event_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS trace_dead_letter (
              event_id TEXT PRIMARY KEY,
              event_json TEXT NOT NULL,
              reason TEXT NOT NULL,
              quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            max_events,
        })
    }

    fn enqueue(&self, event: &TraceEventV2) -> Result<(), AnyError> {
        let event_json = serde_json::to_string(event)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let existing = connection
            .query_row(
                "SELECT event_json FROM trace_spool WHERE event_id=?",
                [&event.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != event_json {
                return Err(format!(
                    "trace event {} conflicts with its durable spool entry",
                    event.event_id
                )
                .into());
            }
            return Ok(());
        }
        let count = connection.query_row("SELECT COUNT(*) FROM trace_spool", [], |row| {
            row.get::<_, i64>(0)
        })?;
        if usize::try_from(count)? >= self.max_events {
            return Err("Trace spool event limit reached".into());
        }
        let inserted = connection.execute(
            r#"INSERT INTO trace_spool(event_id,event_json) VALUES(?,?)
               ON CONFLICT(event_id) DO NOTHING"#,
            params![event.event_id, event_json],
        )?;
        if inserted != 1 {
            return Err("Trace spool insert did not persist exactly one event".into());
        }
        Ok(())
    }

    fn load_batch(&self, limit: usize) -> Result<Vec<TraceEventV2>, AnyError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let mut statement =
            connection.prepare("SELECT event_json FROM trace_spool ORDER BY rowid LIMIT ?")?;
        let rows = statement.query_map([i64::try_from(limit)?], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let event_json = row?;
            serde_json::from_str(&event_json).map_err(AnyError::from)
        })
        .collect()
    }

    fn acknowledge(&self, events: &[TraceEventV2]) -> Result<(), AnyError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let transaction = connection.transaction()?;
        for event in events {
            transaction.execute(
                "DELETE FROM trace_spool WHERE event_id=?",
                [&event.event_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn quarantine(&self, event: &TraceEventV2, reason: &str) -> Result<(), AnyError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT INTO trace_dead_letter(event_id,event_json,reason) VALUES(?,?,?)
               ON CONFLICT(event_id) DO UPDATE SET
                 event_json=excluded.event_json,
                 reason=excluded.reason,
                 quarantined_at=CURRENT_TIMESTAMP"#,
            params![event.event_id, serde_json::to_string(event)?, reason],
        )?;
        transaction.execute(
            "DELETE FROM trace_spool WHERE event_id=?",
            [&event.event_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn stats(&self) -> Result<(u64, u64), AnyError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let pending = connection.query_row("SELECT COUNT(*) FROM trace_spool", [], |row| {
            row.get::<_, i64>(0)
        })?;
        let dead = connection.query_row("SELECT COUNT(*) FROM trace_dead_letter", [], |row| {
            row.get::<_, i64>(0)
        })?;
        Ok((u64::try_from(pending)?, u64::try_from(dead)?))
    }
}

async fn serve_monitoring(bind: SocketAddr, spool: TraceSpool) -> Result<(), AnyError> {
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(trace_readiness))
        .route("/metrics", get(trace_metrics))
        .with_state(spool);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "Trace Adapter monitoring listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn trace_readiness(State(spool): State<TraceSpool>) -> StatusCode {
    let max_events = u64::try_from(spool.max_events).unwrap_or(u64::MAX);
    match tokio::task::spawn_blocking(move || spool.stats()).await {
        Ok(Ok((pending, _))) if pending < max_events => StatusCode::NO_CONTENT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn trace_metrics(State(spool): State<TraceSpool>) -> impl IntoResponse {
    let stats = tokio::task::spawn_blocking(move || spool.stats()).await;
    match stats {
        Ok(Ok((pending, dead))) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            format!(
                concat!(
                    "# TYPE resolver_identity_trace_spool_pending gauge\n",
                    "resolver_identity_trace_spool_pending {}\n",
                    "# TYPE resolver_identity_trace_dead_letter_total gauge\n",
                    "resolver_identity_trace_dead_letter_total {}\n"
                ),
                pending, dead
            ),
        )
            .into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn prepare_socket(path: &Path) -> Result<(), AnyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err("trace socket path exists and is not a Unix socket".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn build_client(settings: &Settings) -> Result<reqwest::Client, AnyError> {
    let mut builder = reqwest::Client::builder()
        .https_only(settings.production)
        .timeout(settings.http_timeout);
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
        _ => return Err("trace TLS client certificate and key must be paired".into()),
    }
    Ok(builder.build()?)
}

fn required(name: &str) -> Result<String, AnyError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
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

fn parse_u64(name: &str, default: u64) -> Result<u64, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

#[cfg(test)]
mod tests {
    use ri_core::evidence::TRACE_EVENT_V2;
    use ri_core::{DnssecStatus, TraceEventKind};

    use super::*;

    #[test]
    fn spool_survives_reopen_and_deletes_only_after_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace-spool.db");
        let event = trace_event("event-1");
        {
            let spool = TraceSpool::open(&path, 100).unwrap();
            spool.enqueue(&event).unwrap();
            spool.enqueue(&event).unwrap();
            let loaded = spool.load_batch(10).unwrap();
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded[0], event);
        }

        let spool = TraceSpool::open(&path, 100).unwrap();
        let recovered = spool.load_batch(10).unwrap();
        assert_eq!(recovered, [event]);
        spool.acknowledge(&recovered).unwrap();
        assert!(spool.load_batch(10).unwrap().is_empty());
    }

    #[test]
    fn spool_rejects_event_id_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let event = trace_event("event-1");
        spool.enqueue(&event).unwrap();
        let mut conflict = event;
        conflict.response_digest =
            Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into());
        assert!(
            spool
                .enqueue(&conflict)
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
    }

    #[test]
    fn rejected_event_moves_to_dead_letter_without_blocking_queue() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let rejected = trace_event("rejected");
        let following = trace_event("following");
        spool.enqueue(&rejected).unwrap();
        spool.enqueue(&following).unwrap();

        spool.quarantine(&rejected, "HTTP 422").unwrap();

        assert_eq!(spool.load_batch(10).unwrap(), [following]);
        assert_eq!(spool.stats().unwrap(), (1, 1));
    }

    fn trace_event(event_id: &str) -> TraceEventV2 {
        TraceEventV2 {
            schema_version: TRACE_EVENT_V2.into(),
            event_id: event_id.into(),
            trace_id: "resolver-trace".into(),
            correlation_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            parent_event_id: None,
            kind: TraceEventKind::ResolverResponse,
            observer_server_id: "operator/r1".into(),
            target_server_id: None,
            target_endpoint: None,
            target_correlation_id: None,
            query_digest: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            response_digest: Some(
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            ),
            observed_at: 1_800_000_000,
            dnssec_status: DnssecStatus::Secure,
            ttl_expires_at: None,
            source_graph_digest: None,
        }
    }
}
