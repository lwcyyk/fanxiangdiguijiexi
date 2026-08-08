use std::collections::HashMap;
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
use ri_core::{TraceEventV2, object_hash};
use ri_store::CacheSourceGraphSelector;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

const MAX_LINE_BYTES: usize = 65_536;
const TRACE_PRODUCER_PROTOCOL: &str = "RI-TRACE/2";
type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    ri_core::install_rustls_crypto_provider()?;
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
    let evidence_store = ri_store::EvidenceStore::open(&settings.evidence_database)?;
    let token = std::fs::read_to_string(&settings.token_file)?
        .trim()
        .to_owned();
    if token.len() < 32 {
        return Err("trace ingestion token must contain at least 32 bytes".into());
    }
    let (sender, receiver) = mpsc::channel(settings.queue_capacity);
    let mut worker = tokio::spawn(upload_worker(UploadWorker {
        receiver,
        spool: spool.clone(),
        evidence_store: evidence_store.clone(),
        client,
        endpoint: format!(
            "{}/v2/trace-events/batch",
            settings.agent_url.trim_end_matches('/')
        ),
        token,
        batch_size: settings.batch_size,
        flush_interval: settings.flush_interval,
        cache_provenance_wait: settings.cache_provenance_wait,
    }));
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
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = Vec::with_capacity(4096);
    let mut durable_ack = false;
    let mut first_line = true;
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
        if first_line && line == TRACE_PRODUCER_PROTOCOL.as_bytes() {
            durable_ack = true;
            first_line = false;
            continue;
        }
        first_line = false;
        let event = serde_json::from_slice::<TraceEventV2>(&line)?;
        let event_id = event.event_id.clone();
        let write_spool = spool.clone();
        tokio::task::spawn_blocking(move || write_spool.enqueue(&event)).await??;
        if durable_ack {
            writer
                .write_all(format!("OK {event_id}\n").as_bytes())
                .await?;
        }
        // Non-blocking hint to the upload worker.  Backpressure is
        // enforced by the spool capacity, not by the channel queue.
        let _ = sender.try_send(());
    }
}

struct UploadWorker {
    receiver: mpsc::Receiver<()>,
    spool: TraceSpool,
    evidence_store: ri_store::EvidenceStore,
    client: reqwest::Client,
    endpoint: String,
    token: String,
    batch_size: usize,
    flush_interval: Duration,
    cache_provenance_wait: Duration,
}

async fn upload_worker(mut worker: UploadWorker) -> Result<(), AnyError> {
    let mut provenance_wait_started = HashMap::<String, tokio::time::Instant>::new();
    loop {
        let mut batch = load_batch_async(&worker.spool, worker.batch_size).await?;
        if batch.is_empty() {
            worker
                .receiver
                .recv()
                .await
                .ok_or("trace event channel closed")?;
            let deadline = tokio::time::Instant::now() + worker.flush_interval;
            while batch.len() < worker.batch_size {
                match tokio::time::timeout_at(deadline, worker.receiver.recv()).await {
                    Ok(Some(())) => {
                        batch = load_batch_async(&worker.spool, worker.batch_size).await?;
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            if batch.is_empty() {
                batch = load_batch_async(&worker.spool, worker.batch_size).await?;
            }
        }
        batch = match prepare_upload_batch(
            &worker.spool,
            &worker.evidence_store,
            batch,
            &mut provenance_wait_started,
            worker.cache_provenance_wait,
        )
        .await?
        {
            BatchPreparation::Ready(batch) => batch,
            BatchPreparation::Waiting => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        process_batch(
            &worker.client,
            &worker.endpoint,
            &worker.token,
            &worker.spool,
            &batch,
        )
        .await?;
        while worker.receiver.try_recv().is_ok() {}
    }
}

enum BatchPreparation {
    Ready(Vec<TraceEventV2>),
    Waiting,
}

async fn prepare_upload_batch(
    spool: &TraceSpool,
    evidence_store: &ri_store::EvidenceStore,
    batch: Vec<TraceEventV2>,
    provenance_wait_started: &mut HashMap<String, tokio::time::Instant>,
    cache_provenance_wait: Duration,
) -> Result<BatchPreparation, AnyError> {
    let Some((index, event)) = batch.iter().enumerate().find(|(_, event)| {
        event.kind == ri_core::TraceEventKind::CacheHit && event.source_graph_digest.is_none()
    }) else {
        return Ok(BatchPreparation::Ready(batch));
    };
    if index > 0 {
        return Ok(BatchPreparation::Ready(batch[..index].to_vec()));
    }
    let cache_object_digest = event
        .cache_object_digest
        .as_deref()
        .ok_or("cache-hit event has no normalized cache object digest")?
        .to_owned();
    let source_store = evidence_store.clone();
    let source = tokio::task::spawn_blocking(move || {
        source_store.find_cache_source_graph(&CacheSourceGraphSelector {
            cache_object_digest: &cache_object_digest,
            graph_digest: None,
        })
    })
    .await??;
    let Some(source) = source else {
        // Earlier Trace rows are uploaded first.  The Wrapper/Agent creates the
        // source graph from those exact rows, after which this event can be
        // enriched without blocking the Resolver's durable spool ACK.
        //
        // When no cache source graph exists at all (e.g. Resolver cache
        // pre-dates the current Registry generation), upload the CacheHit
        // without a source graph digest.  The Agent will build a degraded
        // cache graph with unverified provenance so the Wrapper can still
        // serve the response.
        let started = provenance_wait_started
            .entry(event.event_id.clone())
            .or_insert_with(tokio::time::Instant::now);
        if started.elapsed() >= cache_provenance_wait {
            provenance_wait_started.remove(&event.event_id);
            tracing::warn!(
                trace_id = %event.trace_id,
                event_id = %event.event_id,
                "cache provenance source graph not found; uploading CacheHit without provenance"
            );
            // Do not rewrite sequence numbers — the CacheHit is uploaded,
            // not skipped, so the remaining events keep their original
            // sequence values.
            return Ok(BatchPreparation::Ready(vec![event.clone()]));
        }
        return Ok(BatchPreparation::Waiting);
    };
    let source_digest = object_hash(&source.graph)?;
    if source_digest != source.graph_digest {
        return Err("cache-hit source graph digest does not match stored evidence".into());
    }
    let mut enriched = event.clone();
    enriched.source_graph_digest = Some(source_digest);
    provenance_wait_started.remove(&event.event_id);
    let write_spool = spool.clone();
    let stored = enriched.clone();
    tokio::task::spawn_blocking(move || write_spool.replace_pending(&stored)).await??;
    Ok(BatchPreparation::Ready(vec![enriched]))
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

const MAX_RETRY_ATTEMPTS: u64 = 20;

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
                if attempt >= MAX_RETRY_ATTEMPTS {
                    tracing::error!(
                        attempt,
                        %status,
                        "Max retry attempts exceeded; moving batch to dead letter"
                    );
                    return Ok(UploadDisposition::PayloadRejected {
                        status: status.as_u16(),
                    });
                }
                tracing::warn!(attempt, %status, "Agent temporarily rejected trace batch");
            }
            Err(error) => {
                if attempt >= MAX_RETRY_ATTEMPTS {
                    return Err(format!(
                        "trace batch upload failed after {attempt} attempts: {error}"
                    )
                    .into());
                }
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
    evidence_database: PathBuf,
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
    cache_provenance_wait: Duration,
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
            evidence_database: required("RI_DATABASE")?.into(),
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
            cache_provenance_wait: Duration::from_millis(parse_bounded_u64(
                "RI_TRACE_CACHE_PROVENANCE_WAIT_MS",
                2_000,
                100,
                30_000,
            )?),
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
            CREATE TABLE IF NOT EXISTS trace_spool_seen (
              event_id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              sequence INTEGER NOT NULL,
              event_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(trace_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS trace_spool_state (
              trace_id TEXT PRIMARY KEY,
              last_sequence INTEGER NOT NULL,
              terminal INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let transaction = connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT event_json FROM trace_spool_seen WHERE event_id=?",
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
        let count = transaction.query_row("SELECT COUNT(*) FROM trace_spool", [], |row| {
            row.get::<_, i64>(0)
        })?;
        if usize::try_from(count)? >= self.max_events {
            return Err("Trace spool event limit reached".into());
        }
        let state = transaction
            .query_row(
                "SELECT last_sequence,terminal FROM trace_spool_state WHERE trace_id=?",
                [&event.trace_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let state = state
            .map(|(sequence, terminal)| {
                u64::try_from(sequence)
                    .map(|sequence| (sequence, terminal))
                    .map_err(|_| "stored Trace sequence is negative")
            })
            .transpose()?;
        let expected_sequence = state.as_ref().map_or(1, |value| value.0.saturating_add(1));
        if state.as_ref().is_some_and(|value| value.1)
            || event.sequence != expected_sequence
            || (event.sequence == 1
                && (event.kind != ri_core::TraceEventKind::ClientQuery
                    || event.parent_event_id.is_some()))
        {
            return Err("Trace event is terminal, duplicated, or out of sequence".into());
        }
        if event.sequence > 1 {
            let parent = event
                .parent_event_id
                .as_deref()
                .ok_or("Trace event parent is required")?;
            let parent_sequence = transaction
                .query_row(
                    "SELECT sequence FROM trace_spool_seen WHERE event_id=? AND trace_id=?",
                    params![parent, event.trace_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or("Trace event parent is unknown or belongs to another trace")?;
            let parent_sequence =
                u64::try_from(parent_sequence).map_err(|_| "stored parent sequence is negative")?;
            if parent_sequence >= event.sequence {
                return Err("Trace event parent does not precede its child".into());
            }
        }
        let inserted = transaction.execute(
            r#"INSERT INTO trace_spool(event_id,event_json) VALUES(?,?)
               ON CONFLICT(event_id) DO NOTHING"#,
            params![event.event_id, event_json],
        )?;
        if inserted != 1 {
            return Err("Trace spool insert did not persist exactly one event".into());
        }
        let sequence = i64::try_from(event.sequence)?;
        transaction.execute(
            "INSERT INTO trace_spool_seen(event_id,trace_id,sequence,event_json) VALUES(?,?,?,?)",
            params![event.event_id, event.trace_id, sequence, event_json],
        )?;
        let terminal = matches!(
            event.kind,
            ri_core::TraceEventKind::ClientResponse | ri_core::TraceEventKind::ResolutionFailed
        );
        transaction.execute(
            r#"INSERT INTO trace_spool_state(trace_id,last_sequence,terminal)
               VALUES(?,?,?)
               ON CONFLICT(trace_id) DO UPDATE SET
                 last_sequence=excluded.last_sequence,
                 terminal=excluded.terminal,
                 updated_at=CURRENT_TIMESTAMP"#,
            params![event.trace_id, sequence, terminal],
        )?;
        transaction.commit()?;
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

    fn replace_pending(&self, event: &TraceEventV2) -> Result<(), AnyError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let updated = connection.execute(
            "UPDATE trace_spool SET event_json=? WHERE event_id=?",
            params![serde_json::to_string(event)?, event.event_id],
        )?;
        if updated != 1 {
            return Err("Trace event is no longer pending in the durable spool".into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn fixup_trace_after_cache_hit_skip(
        &self,
        skipped_event: &TraceEventV2,
    ) -> Result<usize, AnyError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let transaction = connection.transaction()?;
        // Check whether the trace is terminal — all events have arrived
        let terminal: bool = transaction
            .query_row(
                "SELECT terminal FROM trace_spool_state WHERE trace_id=?",
                [&skipped_event.trace_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if !terminal {
            return Ok(0);
        }
        let skipped_id = &skipped_event.event_id;
        let new_parent: Option<&str> = skipped_event.parent_event_id.as_deref();
        let skipped_seq = i64::try_from(skipped_event.sequence)?;
        let trace_id = &skipped_event.trace_id;
        // Find all pending events for this trace with sequence above the
        // skipped CacheHit.  Rewrite their sequence numbers and, when the
        // parent was the skipped event, re-parent to the skipped event's
        // own parent.
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT event_id, event_json FROM trace_spool
                 WHERE json_extract(event_json, '$.trace_id') = ?
                   AND CAST(json_extract(event_json, '$.sequence') AS INTEGER) > ?
                 ORDER BY CAST(json_extract(event_json, '$.sequence') AS INTEGER)",
            )?;
            statement
                .query_map(params![trace_id, skipped_seq], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut fixed = 0_usize;
        for (event_id, event_json) in &rows {
            let mut event: TraceEventV2 = serde_json::from_str(event_json)?;
            event.sequence = event.sequence.saturating_sub(1);
            if event.parent_event_id.as_deref() == Some(skipped_id.as_str()) {
                event.parent_event_id = new_parent.map(String::from);
            }
            let new_json = serde_json::to_string(&event)?;
            transaction.execute(
                "UPDATE trace_spool SET event_json=? WHERE event_id=?",
                params![new_json, event_id],
            )?;
            fixed += 1;
        }
        // Trace is no longer terminal after removing the CacheHit — the
        // last event's sequence is now one less.
        if fixed > 0 {
            transaction.execute(
                "UPDATE trace_spool_state SET last_sequence=last_sequence-1 WHERE trace_id=?",
                [trace_id],
            )?;
        }
        transaction.commit()?;
        tracing::info!(
            trace_id = %skipped_event.trace_id,
            fixed,
            "renumbered trace events after skipping CacheHit"
        );
        Ok(fixed)
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

    #[allow(dead_code)]
    fn quarantine_trace(&self, trace_id: &str, reason: &str) -> Result<(), AnyError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "trace spool lock is poisoned")?;
        let transaction = connection.transaction()?;
        let pending = {
            let mut statement = transaction.prepare(
                "SELECT event_id,event_json FROM trace_spool WHERE json_extract(event_json,'$.trace_id')=? ORDER BY rowid",
            )?;
            statement
                .query_map([trace_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if pending.is_empty() {
            return Err("orphan Trace has no pending spool events".into());
        }
        for (event_id, event_json) in pending {
            transaction.execute(
                r#"INSERT INTO trace_dead_letter(event_id,event_json,reason) VALUES(?,?,?)
                   ON CONFLICT(event_id) DO UPDATE SET
                     event_json=excluded.event_json,
                     reason=excluded.reason,
                     quarantined_at=CURRENT_TIMESTAMP"#,
                params![event_id, event_json, reason],
            )?;
            transaction.execute("DELETE FROM trace_spool WHERE event_id=?", [&event_id])?;
        }
        transaction.commit()?;
        tracing::error!(%trace_id, %reason, "orphan Trace moved to dead letter");
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
        // Dead letters are durable historical evidence. They remain visible in
        // metrics, but do not make a recovered adapter permanently unready.
        Ok(Ok((pending, _dead))) if pending < max_events => StatusCode::NO_CONTENT,
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
        .no_proxy()
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

fn parse_bounded_u64(
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, AnyError> {
    let value = parse_u64(name, default)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}").into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use ri_core::evidence::{QUERY_EVIDENCE_GRAPH_V2, TRACE_EVENT_V2};
    use ri_core::{DnssecStatus, QueryEvidenceGraphV2, TraceEventKind, VerificationMode};

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
    fn spool_rejects_out_of_order_terminal_followup_and_capacity_overflow() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 3).unwrap();
        let first = trace_event("first");
        spool.enqueue(&first).unwrap();

        let mut third = first.clone();
        third.event_id = "third".into();
        third.sequence = 3;
        third.parent_event_id = Some(first.event_id.clone());
        assert!(spool.enqueue(&third).is_err());

        let mut terminal = first.clone();
        terminal.event_id = "terminal".into();
        terminal.sequence = 2;
        terminal.parent_event_id = Some(first.event_id.clone());
        terminal.kind = TraceEventKind::ClientResponse;
        terminal.response_digest =
            Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        spool.enqueue(&terminal).unwrap();

        third.parent_event_id = Some(terminal.event_id.clone());
        assert!(spool.enqueue(&third).is_err());

        let other = trace_event("other");
        spool.enqueue(&other).unwrap();
        assert!(
            spool
                .enqueue(&trace_event("overflow"))
                .unwrap_err()
                .to_string()
                .contains("limit")
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

    #[tokio::test]
    async fn enrichment_preserves_seen_event_and_dead_letter_remains_ready() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let original = trace_event("original");
        spool.enqueue(&original).unwrap();
        let mut enriched = original.clone();
        enriched.source_graph_digest =
            Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        spool.replace_pending(&enriched).unwrap();

        assert_eq!(spool.load_batch(10).unwrap(), [enriched]);
        let seen_json = spool
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT event_json FROM trace_spool_seen WHERE event_id=?",
                [&original.event_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<TraceEventV2>(&seen_json).unwrap(),
            original
        );

        spool
            .quarantine_trace(&original.trace_id, "missing cache provenance")
            .unwrap();
        assert_eq!(spool.stats().unwrap(), (0, 1));
        assert_eq!(trace_readiness(State(spool)).await, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn prepare_upload_batch_uses_typed_cache_source_and_persists_recomputed_digest() {
        let directory = tempfile::tempdir().unwrap();
        let evidence_store =
            ri_store::EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let cache_object_digest =
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let source_query_digest =
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let current_query_digest =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let source_digest =
            put_claimed_cache_source(&evidence_store, cache_object_digest, source_query_digest);

        let mut cache_hit = trace_event("current-cache-hit");
        let mut current_query = trace_event_with_trace(&cache_hit.trace_id, "current-query");
        current_query.query_digest = current_query_digest.into();
        cache_hit.sequence = 2;
        cache_hit.parent_event_id = Some(current_query.event_id.clone());
        cache_hit.kind = TraceEventKind::CacheHit;
        cache_hit.query_digest = current_query_digest.into();
        cache_hit.response_digest =
            Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
        cache_hit.cache_object_digest = Some(cache_object_digest.into());
        cache_hit.ttl_expires_at = Some(1_800_000_300);
        spool.enqueue(&current_query).unwrap();
        spool.enqueue(&cache_hit).unwrap();
        let mut waits = HashMap::from([(cache_hit.event_id.clone(), tokio::time::Instant::now())]);

        let prepared = prepare_upload_batch(
            &spool,
            &evidence_store,
            vec![cache_hit.clone()],
            &mut waits,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let BatchPreparation::Ready(events) = prepared else {
            panic!("cache source should make the batch ready");
        };

        assert_eq!(
            source_query_digest,
            evidence_store
                .get_graph("source-trace")
                .unwrap()
                .unwrap()
                .query_digest
        );
        assert_ne!(source_query_digest, current_query_digest);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].source_graph_digest.as_deref(),
            Some(source_digest.as_str())
        );
        let stored = spool
            .load_batch(10)
            .unwrap()
            .into_iter()
            .find(|event| event.event_id == cache_hit.event_id)
            .unwrap();
        assert_eq!(
            stored.source_graph_digest.as_deref(),
            Some(source_digest.as_str())
        );
        assert!(!waits.contains_key(&cache_hit.event_id));
    }

    #[tokio::test]
    async fn prepare_upload_batch_rejects_tampered_cache_source_digest() {
        let directory = tempfile::tempdir().unwrap();
        let evidence_path = directory.path().join("evidence.db");
        let evidence_store = ri_store::EvidenceStore::open(&evidence_path).unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let cache_object_digest =
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        put_claimed_cache_source(
            &evidence_store,
            cache_object_digest,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        Connection::open(&evidence_path)
            .unwrap()
            .execute(
                "UPDATE ri_v2_evidence_graphs SET graph_digest=? WHERE trace_id=?",
                params![
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "source-trace"
                ],
            )
            .unwrap();

        let mut cache_hit = trace_event("tampered-cache-hit");
        let mut current_query = trace_event_with_trace(&cache_hit.trace_id, "tampered-query");
        current_query.query_digest =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        cache_hit.sequence = 2;
        cache_hit.parent_event_id = Some(current_query.event_id.clone());
        cache_hit.kind = TraceEventKind::CacheHit;
        cache_hit.query_digest = current_query.query_digest.clone();
        cache_hit.cache_object_digest = Some(cache_object_digest.into());
        spool.enqueue(&current_query).unwrap();
        spool.enqueue(&cache_hit).unwrap();
        let mut waits = HashMap::new();

        let error = match prepare_upload_batch(
            &spool,
            &evidence_store,
            vec![cache_hit.clone()],
            &mut waits,
            Duration::from_secs(30),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("tampered source digest should reject the batch"),
        };

        assert!(error.to_string().contains("digest does not match"));
        let stored = spool
            .load_batch(10)
            .unwrap()
            .into_iter()
            .find(|event| event.event_id == cache_hit.event_id)
            .unwrap();
        assert!(stored.source_graph_digest.is_none());
    }

    #[test]
    fn cache_hit_skip_spares_remaining_events() {
        // When a CacheHit event is skipped (no source graph), only the
        // CacheHit itself is removed from the spool.  The remaining trace
        // events (including ClientResponse) stay and can be uploaded.
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "resolver-trace-cache-hit-skip";
        let client_query = {
            let mut event = trace_event_with_trace(trace_id, "cq");
            event.trace_id = trace_id.into();
            event
        };
        spool.enqueue(&client_query).unwrap();
        let cache_hit = {
            let mut event = trace_event_with_trace(trace_id, "ch");
            event.trace_id = trace_id.into();
            event.sequence = 2;
            event.parent_event_id = Some("cq".into());
            event.kind = TraceEventKind::CacheHit;
            event.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            event.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            event.ttl_expires_at = Some(1_800_000_000);
            event
        };
        let client_response = {
            let mut event = trace_event_with_trace(trace_id, "cr");
            event.trace_id = trace_id.into();
            event.sequence = 3;
            event.parent_event_id = Some("ch".into());
            event.kind = TraceEventKind::ClientResponse;
            event.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            event.cache_object_digest =
                Some("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into());
            event
        };
        let _cache_hit_id = cache_hit.event_id.clone();
        let client_response_id = client_response.event_id.clone();
        spool.enqueue(&cache_hit).unwrap();
        spool.enqueue(&client_response).unwrap();
        assert_eq!(spool.stats().unwrap(), (3, 0));
        spool.acknowledge(std::slice::from_ref(&cache_hit)).unwrap();
        assert_eq!(spool.stats().unwrap(), (2, 0));
        let loaded = spool.load_batch(10).unwrap();
        assert_eq!(loaded.len(), 2);
        let ids: Vec<_> = loaded.iter().map(|e| &e.event_id).collect();
        assert!(ids.contains(&&"cq".to_string()));
        assert!(ids.contains(&&client_response_id));
    }

    #[test]
    fn normal_trace_passes_through_unblocked() {
        // A normal full-chain trace (ClientQuery, UpstreamQuery,
        // UpstreamResponse, ClientResponse) does not trigger the
        // CacheHit-specific logic and all events remain in the spool.
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "resolver-trace-normal";
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        let upstream_query = {
            let mut e = trace_event_with_trace(trace_id, "uq");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::UpstreamQuery;
            e.target_endpoint = Some(ri_core::DnsEndpoint {
                endpoint_id: None,
                ip: Some("10.0.0.1".into()),
                port: Some(53),
                transport: "udp".into(),
                uri: None,
                server_name: None,
                alpn: vec![],
            });
            e.target_correlation_id =
                Some("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into());
            e.attempt = Some(1);
            e
        };
        spool.enqueue(&upstream_query).unwrap();
        let upstream_response = {
            let mut e = trace_event_with_trace(trace_id, "ur");
            e.trace_id = trace_id.into();
            e.sequence = 3;
            e.parent_event_id = Some("uq".into());
            e.kind = TraceEventKind::UpstreamResponse;
            e.target_endpoint = Some(ri_core::DnsEndpoint {
                endpoint_id: None,
                ip: Some("10.0.0.1".into()),
                port: Some(53),
                transport: "udp".into(),
                uri: None,
                server_name: None,
                alpn: vec![],
            });
            e.target_correlation_id =
                Some("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into());
            e.attempt = Some(1);
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e
        };
        spool.enqueue(&upstream_response).unwrap();
        let client_response = {
            let mut e = trace_event_with_trace(trace_id, "cr");
            e.trace_id = trace_id.into();
            e.sequence = 4;
            e.parent_event_id = Some("ur".into());
            e.kind = TraceEventKind::ClientResponse;
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e.cache_object_digest =
                Some("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into());
            e
        };
        spool.enqueue(&client_response).unwrap();
        assert_eq!(spool.stats().unwrap(), (4, 0));
        let loaded = spool.load_batch(10).unwrap();
        assert_eq!(loaded.len(), 4);
        assert_eq!(loaded[0].kind, TraceEventKind::ClientQuery);
        assert_eq!(loaded[1].kind, TraceEventKind::UpstreamQuery);
        assert_eq!(loaded[2].kind, TraceEventKind::UpstreamResponse);
        assert_eq!(loaded[3].kind, TraceEventKind::ClientResponse);
    }

    #[test]
    fn fixup_renumbers_events_after_cache_hit_skip() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "fixup-renumber";
        // Complete trace: ClientQuery (seq=1) → CacheHit (seq=2) →
        // ClientResponse (seq=3).  The CacheHit is skipped, so
        // ClientResponse must become seq=2 with parent=ClientQuery.
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        let cache_hit = {
            let mut e = trace_event_with_trace(trace_id, "ch");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::CacheHit;
            e.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            e
        };
        spool.enqueue(&cache_hit).unwrap();
        let client_response = {
            let mut e = trace_event_with_trace(trace_id, "cr");
            e.trace_id = trace_id.into();
            e.sequence = 3;
            e.parent_event_id = Some("ch".into());
            e.kind = TraceEventKind::ClientResponse;
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e
        };
        spool.enqueue(&client_response).unwrap();
        assert_eq!(spool.stats().unwrap(), (3, 0));

        let fixed = spool.fixup_trace_after_cache_hit_skip(&cache_hit).unwrap();
        assert_eq!(fixed, 1, "ClientResponse must be fixed");

        // Acknowledge the skipped CacheHit
        spool.acknowledge(std::slice::from_ref(&cache_hit)).unwrap();
        assert_eq!(spool.stats().unwrap(), (2, 0));

        let loaded = spool.load_batch(10).unwrap();
        assert_eq!(loaded.len(), 2);
        let cr = loaded.iter().find(|e| e.event_id == "cr").unwrap();
        assert_eq!(
            cr.sequence, 2,
            "ClientResponse sequence must be decremented"
        );
        assert_eq!(
            cr.parent_event_id.as_deref(),
            Some("cq"),
            "ClientResponse parent must point to ClientQuery"
        );
    }

    #[test]
    fn fixup_preserves_parent_when_not_skipped_event() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "fixup-preserve-parent";
        // UpstreamQuery (seq=2) whose parent is ClientQuery, not CacheHit.
        // When CacheHit at seq=3 is skipped, UpstreamQuery seq should drop to
        // 2 but its parent stays as ClientQuery.
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        let upstream_query = {
            let mut e = trace_event_with_trace(trace_id, "uq");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::UpstreamQuery;
            e
        };
        spool.enqueue(&upstream_query).unwrap();
        let cache_hit = {
            let mut e = trace_event_with_trace(trace_id, "ch");
            e.trace_id = trace_id.into();
            e.sequence = 3;
            e.parent_event_id = Some("uq".into());
            e.kind = TraceEventKind::CacheHit;
            e.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            e
        };
        spool.enqueue(&cache_hit).unwrap();
        let client_response = {
            let mut e = trace_event_with_trace(trace_id, "cr");
            e.trace_id = trace_id.into();
            e.sequence = 4;
            e.parent_event_id = Some("ch".into());
            e.kind = TraceEventKind::ClientResponse;
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e
        };
        spool.enqueue(&client_response).unwrap();
        assert_eq!(spool.stats().unwrap(), (4, 0));

        let fixed = spool.fixup_trace_after_cache_hit_skip(&cache_hit).unwrap();
        // Only ClientResponse is fixed (seq 4→3, parent ch→uq).
        // UpstreamQuery (seq=2) is before the skipped CacheHit (seq=3)
        // and does not need renumbering.
        assert_eq!(fixed, 1);

        spool.acknowledge(std::slice::from_ref(&cache_hit)).unwrap();
        let loaded = spool.load_batch(10).unwrap();
        assert_eq!(loaded.len(), 3);

        let uq = loaded.iter().find(|e| e.event_id == "uq").unwrap();
        assert_eq!(uq.sequence, 2);
        assert_eq!(uq.parent_event_id.as_deref(), Some("cq"));

        let cr = loaded.iter().find(|e| e.event_id == "cr").unwrap();
        // Sequence: 4 → 3 (decremented past the skipped CacheHit)
        assert_eq!(cr.sequence, 3);
        // Parent: ch → uq (re-parented to skipped event's parent)
        assert_eq!(cr.parent_event_id.as_deref(), Some("uq"));
    }

    #[test]
    fn fixup_noop_when_trace_not_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "fixup-no-terminal";
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        // CacheHit arrives but ClientResponse has NOT yet arrived — trace
        // is not terminal.
        let cache_hit = {
            let mut e = trace_event_with_trace(trace_id, "ch");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::CacheHit;
            e.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            e
        };
        spool.enqueue(&cache_hit).unwrap();

        let fixed = spool.fixup_trace_after_cache_hit_skip(&cache_hit).unwrap();
        assert_eq!(fixed, 0, "no fixup when trace is not terminal");
    }

    #[test]
    fn fixup_preserves_idempotency_after_renumber() {
        // After fixup, a re-enqueue of the original (pre-fixup) event must
        // still be idempotent — the trace_spool_seen table keeps the original
        // JSON so that the producer's durable retry matches.
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "fixup-idempotent";
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        let cache_hit = {
            let mut e = trace_event_with_trace(trace_id, "ch");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::CacheHit;
            e.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            e
        };
        spool.enqueue(&cache_hit).unwrap();
        let cr_original = {
            let mut e = trace_event_with_trace(trace_id, "cr");
            e.trace_id = trace_id.into();
            e.sequence = 3;
            e.parent_event_id = Some("ch".into());
            e.kind = TraceEventKind::ClientResponse;
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e
        };
        spool.enqueue(&cr_original).unwrap();

        spool.fixup_trace_after_cache_hit_skip(&cache_hit).unwrap();
        spool.acknowledge(std::slice::from_ref(&cache_hit)).unwrap();

        // Re-enqueue of the original ClientResponse must succeed silently
        spool.enqueue(&cr_original).unwrap();
    }

    #[test]
    fn full_trace_after_fixup_forms_valid_sequence_chain() {
        // End-to-end: the fixed-up events form a valid chain that would
        // pass the Agent's put_trace_events validation.
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let trace_id = "fixup-valid-chain";
        let client_query = {
            let mut e = trace_event_with_trace(trace_id, "cq");
            e.trace_id = trace_id.into();
            e
        };
        spool.enqueue(&client_query).unwrap();
        let cache_hit = {
            let mut e = trace_event_with_trace(trace_id, "ch");
            e.trace_id = trace_id.into();
            e.sequence = 2;
            e.parent_event_id = Some("cq".into());
            e.kind = TraceEventKind::CacheHit;
            e.cache_object_digest =
                Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
            e
        };
        spool.enqueue(&cache_hit).unwrap();
        let client_response = {
            let mut e = trace_event_with_trace(trace_id, "cr");
            e.trace_id = trace_id.into();
            e.sequence = 3;
            e.parent_event_id = Some("ch".into());
            e.kind = TraceEventKind::ClientResponse;
            e.response_digest =
                Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
            e
        };
        spool.enqueue(&client_response).unwrap();

        let fixed = spool.fixup_trace_after_cache_hit_skip(&cache_hit).unwrap();
        assert_eq!(fixed, 1);
        spool.acknowledge(std::slice::from_ref(&cache_hit)).unwrap();

        let loaded = spool.load_batch(10).unwrap();
        assert_eq!(loaded.len(), 2);

        let cq = loaded.iter().find(|e| e.event_id == "cq").unwrap();
        assert_eq!(cq.sequence, 1);
        assert!(cq.parent_event_id.is_none());

        let cr = loaded.iter().find(|e| e.event_id == "cr").unwrap();
        assert_eq!(cr.sequence, 2);
        assert_eq!(cr.parent_event_id.as_deref(), Some("cq"));
        // Sequence chain: 1 → 2 (no gap)
    }

    #[test]
    fn duplicate_event_id_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let spool = TraceSpool::open(&directory.path().join("trace-spool.db"), 100).unwrap();
        let event = trace_event("dedup-id");
        spool.enqueue(&event).unwrap();
        spool.enqueue(&event).unwrap(); // repeat should succeed silently
        assert_eq!(spool.stats().unwrap(), (1, 0));
    }

    fn trace_event(event_id: &str) -> TraceEventV2 {
        trace_event_with_trace(&format!("resolver-trace-{event_id}"), event_id)
    }

    fn put_claimed_cache_source(
        store: &ri_store::EvidenceStore,
        cache_object_digest: &str,
        query_digest: &str,
    ) -> String {
        let response_digest = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let correlation_id = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        store
            .register_query_context(
                "source-trace",
                correlation_id,
                query_digest,
                1_800_000_000,
                1_800_000_300,
            )
            .unwrap();
        let mut query = trace_event_with_trace("producer-trace", "source-query");
        query.correlation_id = correlation_id.into();
        query.query_digest = query_digest.into();
        let mut response = trace_event_with_trace("producer-trace", "source-response");
        response.sequence = 2;
        response.parent_event_id = Some(query.event_id.clone());
        response.kind = TraceEventKind::ClientResponse;
        response.correlation_id = correlation_id.into();
        response.query_digest = query_digest.into();
        response.response_digest = Some(response_digest.into());
        response.cache_object_digest = Some(cache_object_digest.into());
        response.ttl_expires_at = Some(1_800_000_300);
        store.put_trace_events(&[query, response]).unwrap();
        store
            .claim_registered_trace_anchor(
                "source-trace",
                "operator/r1",
                correlation_id,
                query_digest,
                response_digest,
                1_800_000_000,
            )
            .unwrap()
            .unwrap();
        store
            .put_graph(&QueryEvidenceGraphV2 {
                schema_version: QUERY_EVIDENCE_GRAPH_V2.into(),
                trace_id: "source-trace".into(),
                correlation_id: correlation_id.into(),
                challenge: "source-challenge".into(),
                query_digest: query_digest.into(),
                response_digest: response_digest.into(),
                mode: VerificationMode::PublicHybrid,
                entry_server_id: "operator/r1".into(),
                issued_at: 1_800_000_000,
                expires_at: 1_800_000_300,
                dnssec_status: DnssecStatus::Secure,
                cache_provenance: None,
                terminal_cache_graphs: vec![],
                nodes: vec![],
                edges: vec![],
                terminal_node_ids: vec![],
                final_result: true,
                graph_errors: vec![],
                key_id: "test-key".into(),
                signature: None,
            })
            .unwrap()
    }

    fn trace_event_with_trace(trace_id: &str, event_id: &str) -> TraceEventV2 {
        TraceEventV2 {
            schema_version: TRACE_EVENT_V2.into(),
            event_id: event_id.into(),
            trace_id: trace_id.into(),
            sequence: 1,
            correlation_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            parent_event_id: None,
            kind: TraceEventKind::ClientQuery,
            observer_server_id: "operator/r1".into(),
            target_server_id: None,
            target_endpoint: None,
            target_correlation_id: None,
            attempt: None,
            query_digest: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            response_digest: None,
            cache_object_digest: None,
            observed_at: 1_800_000_000,
            dnssec_status: DnssecStatus::Secure,
            ttl_expires_at: None,
            source_graph_digest: None,
            failure_reason: None,
        }
    }
}
