use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use rand::RngCore;
use ri_core::evidence::TRACE_EVENT_V2;
use ri_core::{
    DnsEndpoint, DnssecStatus, TraceEventKind, TraceEventV2, dns_cache_object_digest,
    dns_correlation_id, dns_wire_digest, sha256_hex,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub const MAX_DNS_MESSAGE_SIZE: usize = 65_535;
const MAX_DNS_QUESTIONS: u16 = 16;
type DnsQuestion = (Vec<Vec<u8>>, u16, u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

impl DnsTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthorityProxyConfig {
    pub server_id: String,
    pub public_ip: IpAddr,
    pub public_port: u16,
    pub backend: SocketAddr,
    pub agent_url: String,
    pub trace_ingest_token: String,
    pub backend_timeout: Duration,
    pub agent_timeout: Duration,
    pub max_agent_response_bytes: usize,
}

pub struct AuthorityProxyState {
    config: AuthorityProxyConfig,
    client: reqwest::Client,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
pub struct Metrics {
    queries: AtomicU64,
    accepted: AtomicU64,
    servfail: AtomicU64,
    backend_failures: AtomicU64,
    evidence_failures: AtomicU64,
    inflight: AtomicU64,
    ready: AtomicBool,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("DNS request is malformed: {0}")]
    MalformedDns(String),
    #[error("backend request timed out")]
    BackendTimeout,
    #[error("backend I/O failed: {0}")]
    BackendIo(#[from] std::io::Error),
    #[error("backend returned an invalid DNS response")]
    InvalidBackendResponse,
    #[error("trace ingestion timed out")]
    TraceTimeout,
    #[error("trace ingestion failed: {0}")]
    TraceHttp(#[from] reqwest::Error),
    #[error("trace ingestion returned {0}: {1}")]
    TraceStatus(reqwest::StatusCode, String),
    #[error("trace ingestion response exceeds configured limit")]
    TraceResponseTooLarge,
    #[error("trace construction failed: {0}")]
    TraceConstruction(#[from] ri_core::EvidenceValidationError),
}

impl AuthorityProxyState {
    pub fn new(config: AuthorityProxyConfig, client: reqwest::Client) -> Result<Self, ProxyError> {
        if config.server_id.is_empty() || config.server_id.len() > 256 {
            return Err(ProxyError::MalformedDns(
                "authority server ID is invalid".into(),
            ));
        }
        if config.public_port == 0
            || config.agent_url.is_empty()
            || config.trace_ingest_token.len() < 32
            || config.backend_timeout.is_zero()
            || config.agent_timeout.is_zero()
            || config.max_agent_response_bytes < 1_024
        {
            return Err(ProxyError::MalformedDns(
                "authority proxy configuration is invalid".into(),
            ));
        }
        Ok(Self {
            config,
            client,
            metrics: Arc::new(Metrics::default()),
        })
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    pub async fn process_query(&self, query: &[u8], transport: DnsTransport) -> Vec<u8> {
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        self.metrics.inflight.fetch_add(1, Ordering::Relaxed);
        let result = self.process_query_inner(query, transport).await;
        self.metrics.inflight.fetch_sub(1, Ordering::Relaxed);
        match result {
            Ok(response) => {
                self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                response
            }
            Err(error) => {
                match error {
                    ProxyError::BackendTimeout
                    | ProxyError::BackendIo(_)
                    | ProxyError::InvalidBackendResponse => {
                        self.metrics
                            .backend_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    ProxyError::TraceTimeout
                    | ProxyError::TraceHttp(_)
                    | ProxyError::TraceStatus(_, _)
                    | ProxyError::TraceResponseTooLarge
                    | ProxyError::TraceConstruction(_) => {
                        self.metrics
                            .evidence_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    ProxyError::MalformedDns(_) => {}
                }
                tracing::warn!(%error, "authoritative DNS response rejected");
                self.metrics.servfail.fetch_add(1, Ordering::Relaxed);
                make_servfail(query)
            }
        }
    }

    async fn process_query_inner(
        &self,
        query: &[u8],
        transport: DnsTransport,
    ) -> Result<Vec<u8>, ProxyError> {
        validate_query(query)?;
        let response = timeout(
            self.config.backend_timeout,
            query_backend(query, self.config.backend, transport),
        )
        .await
        .map_err(|_| ProxyError::BackendTimeout)??;
        if !valid_response(query, &response) {
            return Err(ProxyError::InvalidBackendResponse);
        }
        let events = authority_trace_events(
            &self.config.server_id,
            self.config.public_ip,
            self.config.public_port,
            transport,
            query,
            &response,
        )?;
        self.ingest_trace(&events).await?;
        Ok(response)
    }

    async fn ingest_trace(&self, events: &[TraceEventV2]) -> Result<(), ProxyError> {
        let response = timeout(
            self.config.agent_timeout,
            self.client
                .post(format!(
                    "{}/v2/trace-events/batch",
                    self.config.agent_url.trim_end_matches('/')
                ))
                .bearer_auth(&self.config.trace_ingest_token)
                .json(events)
                .send(),
        )
        .await
        .map_err(|_| ProxyError::TraceTimeout)??;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let detail = decode_error_limited(response, self.config.max_agent_response_bytes).await?;
        Err(ProxyError::TraceStatus(status, detail))
    }

    pub async fn probe_agent(&self) -> bool {
        let ready = timeout(
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
        self.metrics.ready.store(ready, Ordering::Relaxed);
        ready
    }
}

pub fn authority_trace_events(
    server_id: &str,
    public_ip: IpAddr,
    public_port: u16,
    transport: DnsTransport,
    query: &[u8],
    response: &[u8],
) -> Result<[TraceEventV2; 2], ProxyError> {
    validate_query(query)?;
    if !valid_response(query, response) {
        return Err(ProxyError::InvalidBackendResponse);
    }
    let mut random = [0_u8; 16];
    rand::rng().fill_bytes(&mut random);
    let trace_id = format!("authority-{}", hex::encode(random));
    let correlation_id = dns_correlation_id(query)?;
    let query_digest = dns_wire_digest(query);
    let response_digest = dns_wire_digest(response);
    let observed_at = unix_time();
    let query_event_id = event_id(&trace_id, 1);
    let response_event_id = event_id(&trace_id, 2);
    let endpoint = DnsEndpoint {
        endpoint_id: None,
        ip: Some(public_ip.to_string()),
        port: Some(public_port),
        transport: transport.as_str().into(),
        uri: None,
        server_name: None,
        alpn: Vec::new(),
    };
    let query_event = TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: query_event_id.clone(),
        trace_id: trace_id.clone(),
        sequence: 1,
        correlation_id: correlation_id.clone(),
        parent_event_id: None,
        kind: TraceEventKind::ClientQuery,
        observer_server_id: server_id.into(),
        target_server_id: None,
        target_endpoint: None,
        target_correlation_id: None,
        attempt: None,
        query_digest: query_digest.clone(),
        response_digest: None,
        cache_object_digest: None,
        observed_at,
        dnssec_status: DnssecStatus::NotApplicable,
        ttl_expires_at: None,
        source_graph_digest: None,
        failure_reason: None,
    };
    let response_event = TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: response_event_id,
        trace_id,
        sequence: 2,
        correlation_id,
        parent_event_id: Some(query_event_id),
        kind: TraceEventKind::AuthorityResponse,
        observer_server_id: server_id.into(),
        target_server_id: None,
        target_endpoint: Some(endpoint),
        target_correlation_id: None,
        attempt: Some(1),
        query_digest,
        response_digest: Some(response_digest),
        cache_object_digest: Some(dns_cache_object_digest(response)?),
        observed_at,
        dnssec_status: DnssecStatus::NotApplicable,
        ttl_expires_at: None,
        source_graph_digest: None,
        failure_reason: None,
    };
    Ok([query_event, response_event])
}

async fn decode_error_limited(
    response: reqwest::Response,
    limit: usize,
) -> Result<String, ProxyError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(ProxyError::TraceResponseTooLarge);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > limit)
        {
            return Err(ProxyError::TraceResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn query_backend(
    query: &[u8],
    backend: SocketAddr,
    transport: DnsTransport,
) -> Result<Vec<u8>, ProxyError> {
    match transport {
        DnsTransport::Udp => {
            let bind = match backend.ip() {
                IpAddr::V4(_) => "0.0.0.0:0",
                IpAddr::V6(_) => "[::]:0",
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(backend).await?;
            socket.send(query).await?;
            let mut response = vec![0_u8; MAX_DNS_MESSAGE_SIZE];
            let size = socket.recv(&mut response).await?;
            response.truncate(size);
            Ok(response)
        }
        DnsTransport::Tcp => {
            let length = u16::try_from(query.len())
                .map_err(|_| ProxyError::MalformedDns("query exceeds TCP DNS limit".into()))?;
            let mut stream = TcpStream::connect(backend).await?;
            stream.write_u16(length).await?;
            stream.write_all(query).await?;
            let length = stream.read_u16().await? as usize;
            if !(12..=MAX_DNS_MESSAGE_SIZE).contains(&length) {
                return Err(ProxyError::InvalidBackendResponse);
            }
            let mut response = vec![0_u8; length];
            stream.read_exact(&mut response).await?;
            Ok(response)
        }
    }
}

pub fn validate_query(query: &[u8]) -> Result<(), ProxyError> {
    if !(12..=MAX_DNS_MESSAGE_SIZE).contains(&query.len()) {
        return Err(ProxyError::MalformedDns(
            "message length is outside the DNS limit".into(),
        ));
    }
    if query[2] & 0x80 != 0 {
        return Err(ProxyError::MalformedDns(
            "client message has the response bit set".into(),
        ));
    }
    let question_count = u16::from_be_bytes([query[4], query[5]]);
    if question_count == 0
        || question_count > MAX_DNS_QUESTIONS
        || question_section(query).is_none()
    {
        return Err(ProxyError::MalformedDns(
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
        && message_is_structurally_complete(response)
        && question_section(query)
            .zip(question_section(response))
            .is_some_and(|(expected, actual)| expected == actual)
}

fn question_section(message: &[u8]) -> Option<Vec<DnsQuestion>> {
    if message.len() < 12 {
        return None;
    }
    let count = u16::from_be_bytes([message[4], message[5]]);
    if count == 0 || count > MAX_DNS_QUESTIONS {
        return None;
    }
    let mut offset = 12;
    let mut questions = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let labels = parse_dns_name(message, &mut offset)?;
        let fields = message.get(offset..offset.checked_add(4)?)?;
        questions.push((
            labels,
            u16::from_be_bytes([fields[0], fields[1]]),
            u16::from_be_bytes([fields[2], fields[3]]),
        ));
        offset += 4;
    }
    Some(questions)
}

fn question_section_end(message: &[u8]) -> Option<usize> {
    if message.len() < 12 {
        return None;
    }
    let count = u16::from_be_bytes([message[4], message[5]]);
    if count == 0 || count > MAX_DNS_QUESTIONS {
        return None;
    }
    let mut offset = 12;
    for _ in 0..count {
        parse_dns_name(message, &mut offset)?;
        offset = offset.checked_add(4)?;
        message.get(..offset)?;
    }
    Some(offset)
}

fn message_is_structurally_complete(message: &[u8]) -> bool {
    let Some(mut offset) = question_section_end(message) else {
        return false;
    };
    let records = [6_usize, 8, 10]
        .into_iter()
        .map(|index| u16::from_be_bytes([message[index], message[index + 1]]))
        .map(usize::from)
        .sum::<usize>();
    for _ in 0..records {
        let mut ignored = offset;
        if parse_dns_name(message, &mut ignored).is_none() {
            return false;
        }
        offset = ignored;
        let Some(header_end) = offset.checked_add(10) else {
            return false;
        };
        let Some(header) = message.get(offset..header_end) else {
            return false;
        };
        let data_length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let Some(record_end) = header_end.checked_add(data_length) else {
            return false;
        };
        if message.get(header_end..record_end).is_none() {
            return false;
        }
        offset = record_end;
    }
    offset == message.len()
}

fn parse_dns_name(message: &[u8], offset: &mut usize) -> Option<Vec<Vec<u8>>> {
    let mut cursor = *offset;
    let mut next = None;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let length = *message.get(cursor)?;
        if length == 0 {
            *offset = next.unwrap_or(cursor + 1);
            return Some(labels);
        }
        if length & 0xc0 == 0xc0 {
            let low = *message.get(cursor + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if pointer >= message.len() || pointer == cursor {
                return None;
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        let start = cursor + 1;
        let end = start.checked_add(usize::from(length))?;
        labels.push(message.get(start..end)?.to_ascii_lowercase());
        cursor = end;
    }
    None
}

pub fn make_servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let question_end = question_section_end(query).unwrap_or(12);
    let mut response = query[..question_end].to_vec();
    response.resize(response.len().max(12), 0);
    response[2] |= 0x80;
    response[2] &= !0x04;
    response[3] = (response[3] & 0xf0) | 0x02;
    response[6..12].fill(0);
    response
}

fn event_id(trace_id: &str, sequence: u64) -> String {
    sha256_hex(format!("authority-trace-event-v1:{trace_id}:{sequence}"))
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

impl Metrics {
    pub fn render(&self) -> String {
        format!(
            concat!(
                "# TYPE resolver_identity_authority_queries_total counter\n",
                "resolver_identity_authority_queries_total {}\n",
                "# TYPE resolver_identity_authority_accepted_total counter\n",
                "resolver_identity_authority_accepted_total {}\n",
                "# TYPE resolver_identity_authority_servfail_total counter\n",
                "resolver_identity_authority_servfail_total {}\n",
                "# TYPE resolver_identity_authority_backend_failures_total counter\n",
                "resolver_identity_authority_backend_failures_total {}\n",
                "# TYPE resolver_identity_authority_evidence_failures_total counter\n",
                "resolver_identity_authority_evidence_failures_total {}\n",
                "# TYPE resolver_identity_authority_inflight gauge\n",
                "resolver_identity_authority_inflight {}\n",
                "# TYPE resolver_identity_authority_ready gauge\n",
                "resolver_identity_authority_ready {}\n"
            ),
            self.queries.load(Ordering::Relaxed),
            self.accepted.load(Ordering::Relaxed),
            self.servfail.load(Ordering::Relaxed),
            self.backend_failures.load(Ordering::Relaxed),
            self.evidence_failures.load(Ordering::Relaxed),
            self.inflight.load(Ordering::Relaxed),
            u64::from(self.ready.load(Ordering::Relaxed)),
        )
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}
