use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use rand::RngCore;
use ri_core::{
    DnsEndpoint, EvidencePolicy, EvidenceValidator, IssuerKeyRegistry, QueryEvidenceGraphV2,
    VerificationMode, dns_correlation_id, dns_wire_digest,
};
use ri_store::{EvidenceStore, StoreError, same_registry_state};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

pub const MAX_DNS_MESSAGE_SIZE: usize = 65_535;
const MAX_DNS_QUESTIONS: u16 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug)]
pub struct Upstream {
    pub address: SocketAddr,
    pub transport: DnsTransport,
}

#[derive(Clone)]
pub struct WrapperConfig {
    pub mode: VerificationMode,
    pub agent_url: String,
    pub agent_api_token: String,
    pub upstreams: Vec<Upstream>,
    pub upstream_timeout: Duration,
    pub agent_timeout: Duration,
    pub transaction_id_reuse_delay: Duration,
    pub max_agent_response_bytes: usize,
    pub max_inflight: usize,
    pub registry_max_staleness_seconds: i64,
}

pub struct WrapperState {
    config: WrapperConfig,
    issuer_keys: IssuerKeyRegistry,
    client: reqwest::Client,
    permits: Arc<Semaphore>,
    metrics: Arc<Metrics>,
    transaction_ids: Arc<TransactionIdPool>,
    registry_store: EvidenceStore,
}

#[derive(Default)]
pub struct Metrics {
    queries: AtomicU64,
    accepted: AtomicU64,
    servfail: AtomicU64,
    overloaded: AtomicU64,
    upstream_failures: AtomicU64,
    verification_failures: AtomicU64,
    inflight: AtomicU64,
    ready: AtomicU64,
}

#[derive(Debug, Error)]
pub enum WrapperError {
    #[error("DNS request is malformed: {0}")]
    MalformedDns(String),
    #[error("all upstreams failed")]
    AllUpstreamsFailed,
    #[error("upstream I/O failed: {0}")]
    UpstreamIo(#[from] std::io::Error),
    #[error("upstream request timed out")]
    UpstreamTimeout,
    #[error("Agent request failed: {0}")]
    AgentHttp(#[from] reqwest::Error),
    #[error("Agent returned {0}: {1}")]
    AgentStatus(reqwest::StatusCode, String),
    #[error("Agent response exceeds configured limit")]
    AgentResponseTooLarge,
    #[error("Agent response is not valid JSON: {0}")]
    AgentResponseJson(#[from] serde_json::Error),
    #[error("Agent request timed out")]
    AgentTimeout,
    #[error("evidence graph DNS binding mismatch")]
    GraphBinding,
    #[error("evidence validation failed: {0}")]
    Evidence(#[from] ri_core::EvidenceValidationError),
    #[error("local Registry state failed: {0}")]
    Store(#[from] StoreError),
    #[error("local Registry evidence mismatch: {0}")]
    RegistryMismatch(String),
    #[error("blocking storage task failed: {0}")]
    BlockingTask(String),
    #[error("no internal DNS transaction ID is available")]
    TransactionIdsExhausted,
}

#[derive(Serialize)]
struct EvidenceGraphRequest<'a> {
    trace_id: &'a str,
    correlation_id: &'a str,
    challenge: &'a str,
    query_digest: &'a str,
    response_digest: &'a str,
    visited_server_ids: Vec<String>,
}

impl WrapperState {
    pub fn new(
        config: WrapperConfig,
        issuer_keys: IssuerKeyRegistry,
        client: reqwest::Client,
        registry_store: EvidenceStore,
    ) -> Result<Self, WrapperError> {
        if config.upstreams.is_empty() {
            return Err(WrapperError::AllUpstreamsFailed);
        }
        if config.max_inflight == 0 || config.max_inflight > usize::from(u16::MAX) {
            return Err(WrapperError::MalformedDns(
                "max_inflight must be between 1 and 65535".into(),
            ));
        }
        if config.transaction_id_reuse_delay < Duration::from_secs(5)
            || config.transaction_id_reuse_delay > Duration::from_secs(300)
        {
            return Err(WrapperError::MalformedDns(
                "transaction ID reuse delay must be between 5 and 300 seconds".into(),
            ));
        }
        if config.max_agent_response_bytes < 1_024 {
            return Err(WrapperError::MalformedDns(
                "Agent response limit must be at least 1024 bytes".into(),
            ));
        }
        if config.registry_max_staleness_seconds <= 0 {
            return Err(WrapperError::RegistryMismatch(
                "Registry staleness limit must be positive".into(),
            ));
        }
        let transaction_ids = Arc::new(TransactionIdPool::new(config.transaction_id_reuse_delay));
        Ok(Self {
            permits: Arc::new(Semaphore::new(config.max_inflight)),
            config,
            issuer_keys,
            client,
            metrics: Arc::new(Metrics::default()),
            transaction_ids,
            registry_store,
        })
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    pub fn record_overload(&self) {
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
        self.metrics.servfail.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn process_query(&self, query: &[u8]) -> Vec<u8> {
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        self.metrics.inflight.fetch_add(1, Ordering::Relaxed);
        let result = self.process_query_inner(query).await;
        self.metrics.inflight.fetch_sub(1, Ordering::Relaxed);
        match result {
            Ok(response) => {
                self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                response
            }
            Err(error) => {
                tracing::warn!(error = %error, "DNS response rejected");
                self.metrics.servfail.fetch_add(1, Ordering::Relaxed);
                make_servfail(query)
            }
        }
    }

    async fn process_query_inner(&self, query: &[u8]) -> Result<Vec<u8>, WrapperError> {
        validate_query(query)?;
        let query_digest = dns_wire_digest(query);
        for upstream in &self.config.upstreams {
            let transaction_id = self.transaction_ids.acquire()?;
            let mut forwarded_query = query.to_vec();
            forwarded_query[..2].copy_from_slice(&transaction_id.id().to_be_bytes());
            let correlation_id = dns_correlation_id(&forwarded_query)?;
            let trace_id = random_hex(16);
            let context_ttl = self
                .config
                .upstream_timeout
                .saturating_add(self.config.agent_timeout)
                .saturating_add(Duration::from_secs(5))
                .as_secs()
                .max(1);
            let registered_at = unix_time();
            let context_trace_id = trace_id.clone();
            let context_correlation_id = correlation_id.clone();
            let context_query_digest = query_digest.clone();
            let expires_at =
                registered_at.saturating_add(i64::try_from(context_ttl).unwrap_or(i64::MAX));
            self.with_store(move |store| {
                store.register_query_context(
                    &context_trace_id,
                    &context_correlation_id,
                    &context_query_digest,
                    registered_at,
                    expires_at,
                )?;
                Ok(())
            })
            .await?;
            let response = match timeout(
                self.config.upstream_timeout,
                query_upstream(&forwarded_query, upstream),
            )
            .await
            {
                Ok(Ok(response)) if valid_response(&forwarded_query, &response) => response,
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                    self.metrics
                        .upstream_failures
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let response_digest = dns_wire_digest(&response);
            match self
                .verify_response(&trace_id, &correlation_id, &query_digest, &response_digest)
                .await
            {
                Ok(()) => {
                    let mut response = response;
                    response[..2].copy_from_slice(&query[..2]);
                    return Ok(response);
                }
                Err(error) => {
                    self.metrics
                        .verification_failures
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        upstream = %upstream.address,
                        error = %error,
                        "upstream evidence rejected"
                    );
                }
            }
        }
        Err(WrapperError::AllUpstreamsFailed)
    }

    async fn verify_response(
        &self,
        trace_id: &str,
        correlation_id: &str,
        query_digest: &str,
        response_digest: &str,
    ) -> Result<(), WrapperError> {
        let challenge = random_hex(32);
        let request = EvidenceGraphRequest {
            trace_id,
            correlation_id,
            challenge: &challenge,
            query_digest,
            response_digest,
            visited_server_ids: vec![],
        };
        let response = timeout(
            self.config.agent_timeout,
            self.client
                .post(format!(
                    "{}/v2/evidence-graph",
                    self.config.agent_url.trim_end_matches('/')
                ))
                .bearer_auth(&self.config.agent_api_token)
                .json(&request)
                .send(),
        )
        .await
        .map_err(|_| WrapperError::AgentTimeout)??;
        if !response.status().is_success() {
            let status = response.status();
            let detail = decode_error_limited(response, 4_096).await;
            return Err(WrapperError::AgentStatus(status, detail));
        }
        let graph = decode_json_limited::<QueryEvidenceGraphV2>(
            response,
            self.config.max_agent_response_bytes,
        )
        .await?;
        if graph.trace_id != trace_id
            || graph.correlation_id != correlation_id
            || graph.query_digest != query_digest
            || graph.response_digest != response_digest
        {
            return Err(WrapperError::GraphBinding);
        }
        let policy = match self.config.mode {
            VerificationMode::ControlledStrict => EvidencePolicy::controlled_strict(),
            VerificationMode::PublicHybrid => EvidencePolicy::public_hybrid(),
        };
        EvidenceValidator {
            policy: &policy,
            issuer_keys: &self.issuer_keys,
        }
        .validate_graph(&graph, &challenge, unix_time())?;
        self.validate_local_registry(&graph, unix_time()).await?;
        Ok(())
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    pub async fn probe_agent(&self) -> bool {
        let agent_ready = timeout(
            self.config.agent_timeout,
            self.client
                .get(format!(
                    "{}/readyz",
                    self.config.agent_url.trim_end_matches('/')
                ))
                .send(),
        )
        .await
        .is_ok_and(|result| result.is_ok_and(|response| response.status().is_success()));
        let ready = agent_ready && self.registry_is_fresh(unix_time()).await.unwrap_or(false);
        self.metrics
            .ready
            .store(u64::from(ready), Ordering::Relaxed);
        ready
    }

    async fn validate_local_registry(
        &self,
        graph: &QueryEvidenceGraphV2,
        now: i64,
    ) -> Result<(), WrapperError> {
        let graph = graph.clone();
        let max_staleness = self.config.registry_max_staleness_seconds;
        self.with_store(move |store| {
            if !registry_is_fresh(&store, now, max_staleness)? {
                return Err(WrapperError::RegistryMismatch(
                    "Registry snapshot heartbeat is stale".into(),
                ));
            }
            for node in &graph.nodes {
                let (local_identity, local_registry) = store
                    .get_identity(&node.identity.server_id)?
                    .ok_or_else(|| {
                        WrapperError::RegistryMismatch(format!(
                            "{} is absent from the local Registry snapshot",
                            node.identity.server_id
                        ))
                    })?;
                if local_identity != node.identity
                    || !same_registry_state(&local_registry, &node.registry)
                    || node.registry.checkpoint_height > local_registry.checkpoint_height
                {
                    return Err(WrapperError::RegistryMismatch(format!(
                        "{} differs from the local Registry snapshot",
                        node.identity.server_id
                    )));
                }
            }
            Ok(())
        })
        .await
    }

    async fn registry_is_fresh(&self, now: i64) -> Result<bool, WrapperError> {
        let max_staleness = self.config.registry_max_staleness_seconds;
        self.with_store(move |store| Ok(registry_is_fresh(&store, now, max_staleness)?))
            .await
    }

    async fn with_store<T, F>(&self, operation: F) -> Result<T, WrapperError>
    where
        T: Send + 'static,
        F: FnOnce(EvidenceStore) -> Result<T, WrapperError> + Send + 'static,
    {
        let store = self.registry_store.clone();
        tokio::task::spawn_blocking(move || operation(store))
            .await
            .map_err(|error| WrapperError::BlockingTask(error.to_string()))?
    }
}

async fn decode_error_limited(response: reqwest::Response, limit: usize) -> String {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return "unreadable error body".into();
        };
        if body.len().saturating_add(chunk.len()) > limit {
            return "error body exceeded 4096 bytes".into();
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).unwrap_or_else(|_| "non-UTF-8 error body".into())
}

fn registry_is_fresh(
    store: &EvidenceStore,
    now: i64,
    max_staleness_seconds: i64,
) -> Result<bool, StoreError> {
    let last_success = store.registry_last_success_epoch()?;
    Ok(last_success > 0
        && last_success <= now.saturating_add(5)
        && now.saturating_sub(last_success) <= max_staleness_seconds)
}

async fn decode_json_limited<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T, WrapperError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(WrapperError::AgentResponseTooLarge);
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(WrapperError::AgentResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

struct TransactionIdPool {
    next: AtomicU64,
    state: Mutex<TransactionIdState>,
    reuse_delay: Duration,
}

#[derive(Default)]
struct TransactionIdState {
    active: HashSet<u16>,
    cooling: HashMap<u16, Instant>,
}

impl TransactionIdPool {
    fn new(reuse_delay: Duration) -> Self {
        Self {
            next: AtomicU64::new(0),
            state: Mutex::new(TransactionIdState::default()),
            reuse_delay,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<TransactionIdPermit, WrapperError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WrapperError::TransactionIdsExhausted)?;
        let now = Instant::now();
        for _ in 0..=u16::MAX {
            let candidate = self.next.fetch_add(1, Ordering::Relaxed) as u16;
            if state.active.contains(&candidate) {
                continue;
            }
            if state
                .cooling
                .get(&candidate)
                .is_some_and(|available_at| *available_at > now)
            {
                continue;
            }
            state.cooling.remove(&candidate);
            if state.active.insert(candidate) {
                return Ok(TransactionIdPermit {
                    id: candidate,
                    pool: Arc::clone(self),
                });
            }
        }
        Err(WrapperError::TransactionIdsExhausted)
    }
}

struct TransactionIdPermit {
    id: u16,
    pool: Arc<TransactionIdPool>,
}

impl TransactionIdPermit {
    fn id(&self) -> u16 {
        self.id
    }
}

impl Drop for TransactionIdPermit {
    fn drop(&mut self) {
        let mut active = self
            .pool
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.active.remove(&self.id);
        active
            .cooling
            .insert(self.id, Instant::now() + self.pool.reuse_delay);
    }
}

impl Metrics {
    pub fn render(&self) -> String {
        format!(
            concat!(
                "# TYPE resolver_identity_dns_queries_total counter\n",
                "resolver_identity_dns_queries_total {}\n",
                "# TYPE resolver_identity_dns_accepted_total counter\n",
                "resolver_identity_dns_accepted_total {}\n",
                "# TYPE resolver_identity_dns_servfail_total counter\n",
                "resolver_identity_dns_servfail_total {}\n",
                "# TYPE resolver_identity_dns_overloaded_total counter\n",
                "resolver_identity_dns_overloaded_total {}\n",
                "# TYPE resolver_identity_upstream_failures_total counter\n",
                "resolver_identity_upstream_failures_total {}\n",
                "# TYPE resolver_identity_verification_failures_total counter\n",
                "resolver_identity_verification_failures_total {}\n",
                "# TYPE resolver_identity_dns_inflight gauge\n",
                "resolver_identity_dns_inflight {}\n",
                "# TYPE resolver_identity_ready gauge\n",
                "resolver_identity_ready {}\n"
            ),
            self.queries.load(Ordering::Relaxed),
            self.accepted.load(Ordering::Relaxed),
            self.servfail.load(Ordering::Relaxed),
            self.overloaded.load(Ordering::Relaxed),
            self.upstream_failures.load(Ordering::Relaxed),
            self.verification_failures.load(Ordering::Relaxed),
            self.inflight.load(Ordering::Relaxed),
            self.ready.load(Ordering::Relaxed)
        )
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed) == 1
    }
}

pub async fn query_upstream(query: &[u8], upstream: &Upstream) -> Result<Vec<u8>, WrapperError> {
    match upstream.transport {
        DnsTransport::Udp => query_udp(query, upstream.address).await,
        DnsTransport::Tcp => query_tcp(query, upstream.address).await,
    }
}

async fn query_udp(query: &[u8], address: SocketAddr) -> Result<Vec<u8>, WrapperError> {
    let bind_address = match address.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(address).await?;
    socket.send(query).await?;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_SIZE];
    let size = socket.recv(&mut response).await?;
    response.truncate(size);
    Ok(response)
}

async fn query_tcp(query: &[u8], address: SocketAddr) -> Result<Vec<u8>, WrapperError> {
    let length = u16::try_from(query.len())
        .map_err(|_| WrapperError::MalformedDns("query exceeds TCP DNS limit".into()))?;
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let response_length = stream.read_u16().await? as usize;
    if response_length < 12 {
        return Err(WrapperError::MalformedDns(
            "upstream TCP response is too short".into(),
        ));
    }
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

pub fn validate_query(query: &[u8]) -> Result<(), WrapperError> {
    if query.len() < 12 {
        return Err(WrapperError::MalformedDns(
            "message is shorter than header".into(),
        ));
    }
    if query.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(WrapperError::MalformedDns(
            "message exceeds DNS size limit".into(),
        ));
    }
    if query[2] & 0x80 != 0 {
        return Err(WrapperError::MalformedDns(
            "client message has the response bit set".into(),
        ));
    }
    let question_count = u16::from_be_bytes([query[4], query[5]]);
    if question_count == 0 {
        return Err(WrapperError::MalformedDns("query has no question".into()));
    }
    if question_count > MAX_DNS_QUESTIONS || parse_questions(query).is_none() {
        return Err(WrapperError::MalformedDns(
            "query question section is invalid".into(),
        ));
    }
    Ok(())
}

pub fn valid_response(query: &[u8], response: &[u8]) -> bool {
    response.len() >= 12
        && response.len() <= MAX_DNS_MESSAGE_SIZE
        && response[0..2] == query[0..2]
        && response[2] & 0x80 != 0
        && response[2] & 0x78 == query[2] & 0x78
        && response[4..6] == query[4..6]
        && parse_questions(query)
            .zip(parse_questions(response))
            .is_some_and(|(expected, actual)| expected == actual)
}

#[derive(Debug, Eq, PartialEq)]
struct DnsQuestion {
    labels: Vec<Vec<u8>>,
    query_type: u16,
    query_class: u16,
}

fn parse_questions(message: &[u8]) -> Option<Vec<DnsQuestion>> {
    if message.len() < 12 {
        return None;
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]);
    if question_count == 0 || question_count > MAX_DNS_QUESTIONS {
        return None;
    }
    let mut offset = 12;
    let mut questions = Vec::with_capacity(usize::from(question_count));
    for _ in 0..question_count {
        let labels = parse_dns_name(message, &mut offset)?;
        let end = offset.checked_add(4)?;
        let fields = message.get(offset..end)?;
        questions.push(DnsQuestion {
            labels,
            query_type: u16::from_be_bytes([fields[0], fields[1]]),
            query_class: u16::from_be_bytes([fields[2], fields[3]]),
        });
        offset = end;
    }
    Some(questions)
}

fn parse_dns_name(message: &[u8], offset: &mut usize) -> Option<Vec<Vec<u8>>> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut visited = HashSet::new();
    let mut labels = Vec::new();
    let mut wire_length = 1_usize;
    loop {
        let length = *message.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *message.get(cursor.checked_add(1)?)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(next);
            if pointer >= message.len() || !visited.insert(pointer) {
                return None;
            }
            if !jumped {
                *offset = cursor.checked_add(2)?;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        cursor = cursor.checked_add(1)?;
        if length == 0 {
            if !jumped {
                *offset = cursor;
            }
            return Some(labels);
        }
        wire_length = wire_length.checked_add(usize::from(length) + 1)?;
        if wire_length > 255 {
            return None;
        }
        let end = cursor.checked_add(usize::from(length))?;
        let label = message.get(cursor..end)?;
        labels.push(label.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>());
        cursor = end;
    }
}

pub fn make_servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut response = query.to_vec();
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80 | (query[3] & 0x10) | 0x02;
    response[6..12].fill(0);
    response
}

pub fn parse_upstream(value: &str) -> Result<Upstream, String> {
    let (transport, address) = value
        .split_once("://")
        .ok_or_else(|| "upstream must use udp:// or tcp://".to_owned())?;
    let transport = match transport.to_ascii_lowercase().as_str() {
        "udp" => DnsTransport::Udp,
        "tcp" => DnsTransport::Tcp,
        _ => return Err("upstream transport must be udp or tcp".into()),
    };
    let address = address
        .parse()
        .map_err(|_| "upstream must contain a numeric IP and port".to_owned())?;
    Ok(Upstream { address, transport })
}

pub fn endpoint_for_upstream(upstream: &Upstream) -> DnsEndpoint {
    DnsEndpoint {
        endpoint_id: None,
        ip: Some(upstream.address.ip().to_string()),
        port: Some(upstream.address.port()),
        transport: match upstream.transport {
            DnsTransport::Udp => "udp",
            DnsTransport::Tcp => "tcp",
        }
        .into(),
        uri: None,
        server_name: None,
        alpn: vec![],
    }
}

fn random_hex(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use ri_core::{dns_correlation_id, dns_wire_digest};

    use super::TransactionIdPool;

    #[test]
    fn active_transaction_ids_are_unique_and_released() {
        let pool = Arc::new(TransactionIdPool::new(Duration::from_secs(1)));
        let first = pool.acquire().unwrap();
        let second = pool.acquire().unwrap();
        assert_ne!(first.id(), second.id());
        assert_eq!(pool.state.lock().unwrap().active.len(), 2);
        drop(first);
        drop(second);
        let state = pool.state.lock().unwrap();
        assert!(state.active.is_empty());
        assert_eq!(state.cooling.len(), 2);
    }

    #[test]
    fn transaction_id_is_not_reused_during_cooldown() {
        let pool = Arc::new(TransactionIdPool::new(Duration::from_millis(20)));
        let first = pool.acquire().unwrap();
        let first_id = first.id();
        drop(first);
        pool.next.store(u64::from(first_id), Ordering::Relaxed);
        let during_cooldown = pool.acquire().unwrap();
        assert_ne!(during_cooldown.id(), first_id);
        drop(during_cooldown);
        std::thread::sleep(Duration::from_millis(25));
        pool.next.store(u64::from(first_id), Ordering::Relaxed);
        let after_cooldown = pool.acquire().unwrap();
        assert_eq!(after_cooldown.id(), first_id);
    }

    #[test]
    fn correlation_binds_internal_id_without_changing_wire_digest() {
        let original = [0x12, 0x34, 0x01, 0x00];
        let internal = [0xab, 0xcd, 0x01, 0x00];
        assert_eq!(dns_wire_digest(&original), dns_wire_digest(&internal));
        assert_ne!(
            dns_correlation_id(&original).unwrap(),
            dns_correlation_id(&internal).unwrap()
        );
    }
}
