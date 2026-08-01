use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use ri_core::evidence::{
    QUERY_EVIDENCE_GRAPH_V2, SERVER_HOP_EVIDENCE_V2, TARGET_RESPONSE_ATTESTATION_V2, TRACE_EVENT_V2,
};
use ri_core::{
    CacheProvenanceV2, DnsEndpoint, DnsServerIdentityV2, DnssecStatus, EvidenceLevel,
    EvidenceNodeV2, EvidencePolicy, EvidenceValidator, IssuerKeyRegistry, QueryEvidenceGraphV2,
    RegistryReferenceV2, ServerHopEvidenceV2, TargetResponseAttestationV2, TraceEventKind,
    TraceEventV2, VerificationMode, sign_ed25519,
};
use ri_store::{EvidenceStore, StoreError, TraceResponseMatch, same_registry_state};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::limit::ConcurrencyLimitLayer;

#[derive(Clone)]
pub struct AgentState {
    pub config: AgentConfig,
    pub store: EvidenceStore,
    pub issuer_keys: IssuerKeyRegistry,
    client: reqwest::Client,
    metrics: Arc<AgentMetrics>,
}

#[derive(Default)]
struct AgentMetrics {
    graph_requests: AtomicU64,
    graph_failures: AtomicU64,
    trace_events_ingested: AtomicU64,
}

#[derive(Clone)]
pub struct AgentConfig {
    pub server_id: String,
    pub private_key_b64: String,
    pub key_id: String,
    pub mode: VerificationMode,
    pub max_age_seconds: i64,
    pub trace_wait_millis: u64,
    pub max_cache_ttl_seconds: i64,
    pub registry_max_staleness_seconds: i64,
    pub trace_ingest_token: String,
    pub wrapper_api_token: String,
    pub peer_api_token: String,
    pub max_concurrent_requests: usize,
    pub max_request_body_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceGraphRequest {
    pub trace_id: String,
    pub correlation_id: String,
    pub challenge: String,
    pub query_digest: String,
    pub response_digest: String,
    #[serde(default)]
    pub visited_server_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResponseAttestationRequest {
    pub trace_id: String,
    pub correlation_id: String,
    pub challenge: String,
    pub query_digest: String,
    pub response_digest: String,
    pub endpoint: DnsEndpoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct IssuerKeyFile {
    keys: Vec<IssuerKeyRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct IssuerKeyRecord {
    issuer: String,
    key_id: String,
    algorithm: String,
    public_key: String,
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("identity evidence unavailable: {0}")]
    EvidenceUnavailable(String),
    #[error("downstream Agent failed: {0}")]
    Downstream(String),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("validation error: {0}")]
    Validation(#[from] ri_core::EvidenceValidationError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("blocking storage task failed: {0}")]
    BlockingTask(String),
}

impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::EvidenceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Downstream(_) => StatusCode::BAD_GATEWAY,
            Self::Store(_)
            | Self::Validation(_)
            | Self::Serialization(_)
            | Self::Http(_)
            | Self::BlockingTask(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({"ok": false, "error": self.to_string()})),
        )
            .into_response()
    }
}

impl AgentState {
    pub fn new(
        config: AgentConfig,
        store: EvidenceStore,
        issuer_keys: IssuerKeyRegistry,
        client: reqwest::Client,
    ) -> Self {
        Self {
            config,
            store,
            issuer_keys,
            client,
            metrics: Arc::new(AgentMetrics::default()),
        }
    }

    async fn with_store<T, F>(&self, operation: F) -> Result<T, AgentError>
    where
        T: Send + 'static,
        F: FnOnce(EvidenceStore) -> Result<T, AgentError> + Send + 'static,
    {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || operation(store))
            .await
            .map_err(|error| AgentError::BlockingTask(error.to_string()))?
    }

    pub fn load_issuer_keys(path: &std::path::Path) -> Result<IssuerKeyRegistry, AgentError> {
        let data = std::fs::read_to_string(path)
            .map_err(|error| AgentError::EvidenceUnavailable(error.to_string()))?;
        let file: IssuerKeyFile = serde_json::from_str(&data)?;
        if file.keys.is_empty() {
            return Err(AgentError::InvalidRequest(
                "issuer key bundle is empty".into(),
            ));
        }
        let mut registry = IssuerKeyRegistry::default();
        let mut key_ids = HashSet::new();
        for key in file.keys {
            if key.issuer.is_empty()
                || key.key_id.is_empty()
                || key.public_key.is_empty()
                || !key.algorithm.eq_ignore_ascii_case("ed25519")
            {
                return Err(AgentError::InvalidRequest(
                    "issuer key record is invalid".into(),
                ));
            }
            if !key_ids.insert((key.issuer.clone(), key.key_id.clone())) {
                return Err(AgentError::InvalidRequest(
                    "issuer key bundle contains a duplicate issuer/key_id".into(),
                ));
            }
            registry.insert(key.issuer, key.key_id, key.public_key);
        }
        Ok(registry)
    }

    pub async fn build_graph(
        &self,
        request: &EvidenceGraphRequest,
    ) -> Result<QueryEvidenceGraphV2, AgentError> {
        self.build_graph_with_context(request, false).await
    }

    async fn build_graph_with_context(
        &self,
        request: &EvidenceGraphRequest,
        require_registered_context: bool,
    ) -> Result<QueryEvidenceGraphV2, AgentError> {
        validate_request(
            &request.trace_id,
            &request.correlation_id,
            &request.challenge,
            &request.query_digest,
            &request.response_digest,
        )?;
        let now = unix_time();
        self.require_fresh_registry(now).await?;
        if request.visited_server_ids.len() > 64 {
            return Err(AgentError::InvalidRequest(
                "visited server list exceeds maximum depth".into(),
            ));
        }
        if request
            .visited_server_ids
            .iter()
            .any(|server_id| server_id == &self.config.server_id)
        {
            return Err(AgentError::EvidenceUnavailable(format!(
                "Agent graph loop detected at {}",
                self.config.server_id
            )));
        }
        let server_id = self.config.server_id.clone();
        let self_record = self
            .with_store(move |store| Ok(store.get_identity(&server_id)?))
            .await?
            .ok_or_else(|| {
                AgentError::EvidenceUnavailable(format!(
                    "local identity {} not found",
                    self.config.server_id
                ))
            })?;
        let anchor = self
            .wait_for_trace_anchor(request, require_registered_context)
            .await?;
        // Knot can only classify the complete client answer after consuming all
        // DNSKEY, DS, and answer exchanges. Intermediate upstream packets are
        // therefore bound causally here, while the terminal Resolver verdict
        // supplies the DNSSEC result for the complete resolution context.
        let resolver_dnssec_status = anchor.dnssec_status;
        let anchor_trace_id = anchor.trace_id.clone();
        let events = self
            .with_store(move |store| Ok(store.trace_events(&anchor_trace_id)?))
            .await?;
        let cache_hit = events.iter().rev().find(|event| {
            event.observer_server_id == self.config.server_id
                && event.correlation_id == request.correlation_id
                && event.kind == TraceEventKind::CacheHit
                && event.query_digest == request.query_digest
                && event.response_digest.as_deref() == Some(request.response_digest.as_str())
        });
        let mut upstream_responses = events
            .iter()
            .filter(|event| event.kind == TraceEventKind::UpstreamResponse)
            .filter_map(|event| {
                event
                    .parent_event_id
                    .as_ref()
                    .map(|parent| (parent.clone(), event.clone()))
            })
            .collect::<HashMap<_, _>>();
        let mut upstream_timeouts = events
            .iter()
            .filter(|event| event.kind == TraceEventKind::UpstreamTimeout)
            .filter_map(|event| {
                event
                    .parent_event_id
                    .as_ref()
                    .map(|parent| (parent.clone(), event.clone()))
            })
            .collect::<HashMap<_, _>>();
        let outbound = events
            .iter()
            .filter(|event| {
                event.observer_server_id == self.config.server_id
                    && event.correlation_id == request.correlation_id
                    && matches!(
                        event.kind,
                        TraceEventKind::UpstreamQuery
                            | TraceEventKind::ResolverQuery
                            | TraceEventKind::AuthorityQuery
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        if outbound.is_empty() {
            return self
                .build_cache_hit_graph(request, self_record, cache_hit, now)
                .await;
        }

        let mut nodes = HashMap::<String, EvidenceNodeV2>::new();
        nodes.insert(
            self_record.0.server_id.clone(),
            evidence_node(
                self_record.0,
                self_record.1,
                vec![EvidenceLevel::RegistryBound, EvidenceLevel::AgentAttested],
            ),
        );
        let mut edges = Vec::with_capacity(outbound.len());
        let mut terminal_cache_graphs = Vec::new();
        for event in outbound {
            let target_endpoint = event.target_endpoint.clone().ok_or_else(|| {
                AgentError::EvidenceUnavailable(format!(
                    "trace event {} has no target endpoint",
                    event.event_id
                ))
            })?;
            let response_event = if event.kind == TraceEventKind::UpstreamQuery {
                if let Some(response) = upstream_responses.remove(&event.event_id) {
                    response
                } else if let Some(timeout) = upstream_timeouts.remove(&event.event_id) {
                    if timeout.sequence <= event.sequence
                        || timeout.correlation_id != event.correlation_id
                        || timeout.query_digest != event.query_digest
                        || timeout.target_correlation_id != event.target_correlation_id
                        || timeout.target_endpoint != event.target_endpoint
                        || timeout.attempt != event.attempt
                    {
                        return Err(AgentError::EvidenceUnavailable(format!(
                            "outbound timeout for {} violates causal binding",
                            event.event_id
                        )));
                    }
                    continue;
                } else {
                    return Err(AgentError::EvidenceUnavailable(format!(
                        "outbound trace event {} has no causally bound response or timeout",
                        event.event_id
                    )));
                }
            } else {
                event.clone()
            };
            if event.kind == TraceEventKind::UpstreamQuery
                && (response_event.sequence <= event.sequence
                    || response_event.correlation_id != event.correlation_id
                    || response_event.query_digest != event.query_digest
                    || response_event.target_correlation_id != event.target_correlation_id
                    || response_event.target_endpoint != event.target_endpoint
                    || response_event.attempt != event.attempt)
            {
                return Err(AgentError::EvidenceUnavailable(format!(
                    "outbound response for {} violates causal binding",
                    event.event_id
                )));
            }
            let response_digest = response_event.response_digest.clone().ok_or_else(|| {
                AgentError::EvidenceUnavailable(format!(
                    "response event {} has no response digest",
                    response_event.event_id
                ))
            })?;
            let lookup_endpoint = target_endpoint.clone();
            let (target_identity, target_registry) = self
                .with_store(move |store| Ok(store.lookup_identity(&lookup_endpoint)?))
                .await?
                .ok_or_else(|| {
                    AgentError::EvidenceUnavailable(format!(
                        "target identity not found for {}",
                        target_endpoint.cache_key().unwrap_or_default()
                    ))
                })?;
            if event
                .target_server_id
                .as_deref()
                .is_some_and(|server_id| server_id != target_identity.server_id)
            {
                return Err(AgentError::EvidenceUnavailable(format!(
                    "trace event {} target identity mismatch",
                    event.event_id
                )));
            }
            let target_correlation_id = target_correlation(&event)?;
            let target_attestation = self
                .fetch_target_attestation(
                    &target_identity,
                    &ResponseAttestationRequest {
                        trace_id: request.trace_id.clone(),
                        correlation_id: target_correlation_id.clone(),
                        challenge: request.challenge.clone(),
                        query_digest: event.query_digest.clone(),
                        response_digest: response_digest.clone(),
                        endpoint: target_endpoint.clone(),
                    },
                )
                .await?;
            let mut levels = vec![EvidenceLevel::RegistryBound];
            if target_attestation.is_some() {
                levels.push(EvidenceLevel::AgentAttested);
            }
            if resolver_dnssec_status == DnssecStatus::Secure {
                levels.push(EvidenceLevel::DnssecValidated);
            }
            merge_node(
                &mut nodes,
                evidence_node(target_identity.clone(), target_registry.clone(), levels),
            )?;
            let from_endpoint = self_record_endpoint(&nodes, &self.config.server_id)?;
            let mut edge = ServerHopEvidenceV2 {
                schema_version: SERVER_HOP_EVIDENCE_V2.into(),
                edge_id: format!("{}:{}", request.trace_id, event.event_id),
                trace_id: request.trace_id.clone(),
                target_correlation_id: target_correlation_id.clone(),
                challenge: request.challenge.clone(),
                from_server_id: self.config.server_id.clone(),
                to_server_id: target_identity.server_id.clone(),
                from_endpoint,
                to_endpoint: target_endpoint,
                query_digest: event.query_digest.clone(),
                response_digest: response_digest.clone(),
                observed_at: response_event.observed_at,
                issued_at: now,
                expires_at: now + self.config.max_age_seconds,
                accepted: true,
                reasons: vec![],
                registry: target_registry.clone(),
                target_attestation,
                key_id: self.config.key_id.clone(),
                signature: None,
            };
            edge.signature = Some(sign_ed25519(&edge, &self.config.private_key_b64)?);
            edges.push(edge);

            if target_identity.role.is_recursive() {
                let child = self
                    .fetch_target_graph(
                        &target_identity,
                        EvidenceGraphRequest {
                            trace_id: request.trace_id.clone(),
                            correlation_id: target_correlation_id,
                            challenge: request.challenge.clone(),
                            query_digest: event.query_digest,
                            response_digest,
                            visited_server_ids: request
                                .visited_server_ids
                                .iter()
                                .cloned()
                                .chain(std::iter::once(self.config.server_id.clone()))
                                .collect(),
                        },
                    )
                    .await?;
                if let Some(child) = child {
                    if child.entry_server_id != target_identity.server_id {
                        return Err(AgentError::Downstream(
                            "downstream graph entry identity mismatch".into(),
                        ));
                    }
                    let child_entry = child
                        .nodes
                        .iter()
                        .find(|node| node.identity.server_id == child.entry_server_id)
                        .ok_or_else(|| {
                            AgentError::Downstream("downstream graph entry node is missing".into())
                        })?;
                    if child_entry.identity != target_identity
                        || !same_registry_state(&child_entry.registry, &target_registry)
                    {
                        return Err(AgentError::Downstream(
                            "downstream graph entry Registry state mismatch".into(),
                        ));
                    }
                    for node in child.nodes.iter().cloned() {
                        if node.identity.server_id == target_identity.server_id {
                            continue;
                        }
                        merge_node(&mut nodes, node)?;
                    }
                    if child.cache_provenance.is_some() {
                        terminal_cache_graphs.push(child);
                    } else {
                        edges.extend(child.edges);
                        terminal_cache_graphs.extend(child.terminal_cache_graphs);
                    }
                }
            }
        }

        let terminal_node_ids = terminal_nodes(&nodes, &edges, &self.config.server_id);
        let dnssec_status = aggregate_dnssec_status(&edges, &nodes, &terminal_cache_graphs);
        let mut graph = QueryEvidenceGraphV2 {
            schema_version: QUERY_EVIDENCE_GRAPH_V2.into(),
            trace_id: request.trace_id.clone(),
            correlation_id: request.correlation_id.clone(),
            challenge: request.challenge.clone(),
            query_digest: request.query_digest.clone(),
            response_digest: request.response_digest.clone(),
            mode: self.config.mode,
            entry_server_id: self.config.server_id.clone(),
            issued_at: now,
            expires_at: now + self.config.max_age_seconds,
            dnssec_status,
            cache_provenance: None,
            terminal_cache_graphs,
            nodes: nodes.into_values().collect(),
            edges,
            terminal_node_ids,
            final_result: true,
            graph_errors: vec![],
            key_id: self.config.key_id.clone(),
            signature: None,
        };
        graph
            .nodes
            .sort_by(|left, right| left.identity.server_id.cmp(&right.identity.server_id));
        graph
            .edges
            .sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        graph
            .terminal_cache_graphs
            .sort_by(|left, right| left.entry_server_id.cmp(&right.entry_server_id));
        graph.signature = Some(sign_ed25519(&graph, &self.config.private_key_b64)?);

        let policy = match self.config.mode {
            VerificationMode::ControlledStrict => EvidencePolicy::controlled_strict(),
            VerificationMode::PublicHybrid => EvidencePolicy::public_hybrid(),
        };
        EvidenceValidator {
            policy: &policy,
            issuer_keys: &self.issuer_keys,
        }
        .validate_graph(&graph, &request.challenge, now)?;
        let stored_graph = graph.clone();
        self.with_store(move |store| {
            store.put_graph(&stored_graph)?;
            Ok(())
        })
        .await?;
        Ok(graph)
    }

    async fn build_cache_hit_graph(
        &self,
        request: &EvidenceGraphRequest,
        self_record: (DnsServerIdentityV2, RegistryReferenceV2),
        cache_hit: Option<&TraceEventV2>,
        now: i64,
    ) -> Result<QueryEvidenceGraphV2, AgentError> {
        let cache_hit = cache_hit.ok_or_else(|| {
            AgentError::EvidenceUnavailable(
                "trace has neither outbound queries nor a cache-hit event".into(),
            )
        })?;
        let ttl_expires_at = cache_hit.ttl_expires_at.ok_or_else(|| {
            AgentError::EvidenceUnavailable("cache-hit event has no TTL boundary".into())
        })?;
        if ttl_expires_at <= now
            || ttl_expires_at > now.saturating_add(self.config.max_cache_ttl_seconds)
        {
            return Err(AgentError::EvidenceUnavailable(
                "cache-hit TTL is outside policy".into(),
            ));
        }
        let query_digest = request.query_digest.clone();
        let cache_object_digest = cache_hit.cache_object_digest.clone().ok_or_else(|| {
            AgentError::EvidenceUnavailable(
                "cache-hit event has no normalized cache object digest".into(),
            )
        })?;
        let source_digest = cache_hit.source_graph_digest.as_deref().ok_or_else(|| {
            AgentError::EvidenceUnavailable(
                "cache-hit event does not declare its source graph digest".into(),
            )
        })?;
        let claimed_source_digest = source_digest.to_owned();
        let source_graph = self
            .with_store(move |store| {
                Ok(store.find_cache_source_graph_by_digest(
                    &query_digest,
                    &cache_object_digest,
                    &claimed_source_digest,
                )?)
            })
            .await?
            .ok_or_else(|| {
                AgentError::EvidenceUnavailable(
                    "cache-hit source graph is absent from the current Registry generation".into(),
                )
            })?;
        if cache_hit.dnssec_status != source_graph.dnssec_status {
            return Err(AgentError::EvidenceUnavailable(
                "cache-hit DNSSEC status differs from source evidence".into(),
            ));
        }
        let source_dnssec_required = graph_requires_dnssec(&source_graph);
        if source_dnssec_required && source_graph.dnssec_status != DnssecStatus::Secure {
            return Err(AgentError::EvidenceUnavailable(
                "cache source graph does not preserve required DNSSEC evidence".into(),
            ));
        }
        let identity_expires_at = source_graph
            .nodes
            .iter()
            .map(|node| node.identity.valid_until)
            .min()
            .ok_or_else(|| {
                AgentError::EvidenceUnavailable("cache source graph has no identities".into())
            })?;
        let snapshot_generation = self_record.1.snapshot_generation;
        let entry_server_id = self_record.0.server_id.clone();
        let mut graph = QueryEvidenceGraphV2 {
            schema_version: QUERY_EVIDENCE_GRAPH_V2.into(),
            trace_id: request.trace_id.clone(),
            correlation_id: request.correlation_id.clone(),
            challenge: request.challenge.clone(),
            query_digest: request.query_digest.clone(),
            response_digest: request.response_digest.clone(),
            mode: self.config.mode,
            entry_server_id: entry_server_id.clone(),
            issued_at: now,
            expires_at: now + self.config.max_age_seconds,
            dnssec_status: source_graph.dnssec_status,
            cache_provenance: Some(CacheProvenanceV2 {
                source_graph_digest: source_digest.to_owned(),
                source_dnssec_required,
                cached_at: cache_hit.observed_at,
                dns_ttl_expires_at: ttl_expires_at,
                identity_expires_at,
                snapshot_generation,
            }),
            terminal_cache_graphs: vec![],
            nodes: vec![evidence_node(
                self_record.0,
                self_record.1,
                vec![EvidenceLevel::RegistryBound, EvidenceLevel::AgentAttested],
            )],
            edges: vec![],
            terminal_node_ids: vec![entry_server_id],
            final_result: true,
            graph_errors: vec![],
            key_id: self.config.key_id.clone(),
            signature: None,
        };
        graph.signature = Some(sign_ed25519(&graph, &self.config.private_key_b64)?);
        let policy = match self.config.mode {
            VerificationMode::ControlledStrict => EvidencePolicy::controlled_strict(),
            VerificationMode::PublicHybrid => EvidencePolicy::public_hybrid(),
        };
        EvidenceValidator {
            policy: &policy,
            issuer_keys: &self.issuer_keys,
        }
        .validate_graph(&graph, &request.challenge, now)?;
        let stored_graph = graph.clone();
        self.with_store(move |store| {
            store.put_graph(&stored_graph)?;
            Ok(())
        })
        .await?;
        Ok(graph)
    }

    pub async fn attest_response(
        &self,
        request: &ResponseAttestationRequest,
    ) -> Result<TargetResponseAttestationV2, AgentError> {
        validate_request(
            &request.trace_id,
            &request.correlation_id,
            &request.challenge,
            &request.query_digest,
            &request.response_digest,
        )?;
        let now = unix_time();
        self.require_fresh_registry(now).await?;
        let server_id = self.config.server_id.clone();
        let (identity, _) = self
            .with_store(move |store| Ok(store.get_identity(&server_id)?))
            .await?
            .ok_or_else(|| AgentError::EvidenceUnavailable("local identity missing".into()))?;
        if !identity
            .endpoints
            .iter()
            .any(|endpoint| endpoint.matches(&request.endpoint).unwrap_or(false))
        {
            return Err(AgentError::EvidenceUnavailable(
                "attested endpoint is not bound to local identity".into(),
            ));
        }
        let response_event = self.wait_for_matching_response(request).await?;
        let mut attestation = TargetResponseAttestationV2 {
            schema_version: TARGET_RESPONSE_ATTESTATION_V2.into(),
            target_server_id: self.config.server_id.clone(),
            trace_id: request.trace_id.clone(),
            correlation_id: request.correlation_id.clone(),
            challenge: request.challenge.clone(),
            query_digest: request.query_digest.clone(),
            response_digest: request.response_digest.clone(),
            endpoint: request.endpoint.clone(),
            observed_at: response_event.observed_at,
            issued_at: now,
            expires_at: now + self.config.max_age_seconds,
            key_id: self.config.key_id.clone(),
            signature: None,
        };
        attestation.signature = Some(sign_ed25519(&attestation, &self.config.private_key_b64)?);
        Ok(attestation)
    }

    async fn fetch_target_attestation(
        &self,
        target: &DnsServerIdentityV2,
        request: &ResponseAttestationRequest,
    ) -> Result<Option<TargetResponseAttestationV2>, AgentError> {
        let service_url = target
            .agent
            .as_ref()
            .and_then(|agent| agent.service_url.as_deref());
        let Some(service_url) = service_url else {
            if self.config.mode == VerificationMode::ControlledStrict {
                return Err(AgentError::EvidenceUnavailable(format!(
                    "{} does not publish an Agent URL",
                    target.server_id
                )));
            }
            return Ok(None);
        };
        let response = self
            .client
            .post(format!(
                "{}/v2/attest-response",
                service_url.trim_end_matches('/')
            ))
            .bearer_auth(&self.config.peer_api_token)
            .json(request)
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => Ok(Some(
                decode_json_limited(
                    response,
                    self.config.max_request_body_bytes,
                    "target attestation",
                )
                .await?,
            )),
            Ok(response) if self.config.mode == VerificationMode::PublicHybrid => {
                tracing::warn!(
                    target = %target.server_id,
                    status = %response.status(),
                    "optional public target Agent did not attest"
                );
                Ok(None)
            }
            Ok(response) => Err(AgentError::Downstream(format!(
                "{} returned {}",
                target.server_id,
                response.status()
            ))),
            Err(error) if self.config.mode == VerificationMode::PublicHybrid => {
                tracing::warn!(
                    target = %target.server_id,
                    error = %error,
                    "optional public target Agent is unavailable"
                );
                Ok(None)
            }
            Err(error) => Err(AgentError::Http(error)),
        }
    }

    async fn require_fresh_registry(&self, now: i64) -> Result<(), AgentError> {
        let last_success = self
            .with_store(|store| Ok(store.registry_last_success_epoch()?))
            .await?;
        if last_success <= 0
            || last_success > now + 5
            || now - last_success > self.config.registry_max_staleness_seconds
        {
            return Err(AgentError::EvidenceUnavailable(
                "Registry snapshot heartbeat is stale".into(),
            ));
        }
        Ok(())
    }

    async fn wait_for_matching_response(
        &self,
        request: &ResponseAttestationRequest,
    ) -> Result<TraceEventV2, AgentError> {
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(self.config.trace_wait_millis);
        loop {
            let request_trace_id = request.trace_id.clone();
            let server_id = self.config.server_id.clone();
            let correlation_id = request.correlation_id.clone();
            let query_digest = request.query_digest.clone();
            let response_digest = request.response_digest.clone();
            let endpoint = request.endpoint.clone();
            let event = self
                .with_store(move |store| {
                    Ok(store.claim_matching_response(&TraceResponseMatch {
                        request_trace_id: &request_trace_id,
                        server_id: &server_id,
                        correlation_id: &correlation_id,
                        query_digest: &query_digest,
                        response_digest: &response_digest,
                        endpoint: Some(&endpoint),
                        allow_authority_response: true,
                    })?)
                })
                .await?;
            if let Some(event) = event {
                return Ok(event);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::EvidenceUnavailable(
                    "matching local DNS response event not found".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_trace_anchor(
        &self,
        request: &EvidenceGraphRequest,
        require_registered_context: bool,
    ) -> Result<TraceEventV2, AgentError> {
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(self.config.trace_wait_millis);
        loop {
            let anchor = if require_registered_context {
                let request_trace_id = request.trace_id.clone();
                let server_id = self.config.server_id.clone();
                let correlation_id = request.correlation_id.clone();
                let query_digest = request.query_digest.clone();
                let response_digest = request.response_digest.clone();
                self.with_store(move |store| {
                    Ok(store.claim_registered_trace_anchor(
                        &request_trace_id,
                        &server_id,
                        &correlation_id,
                        &query_digest,
                        &response_digest,
                        unix_time(),
                    )?)
                })
                .await?
            } else {
                let request_trace_id = request.trace_id.clone();
                let server_id = self.config.server_id.clone();
                let correlation_id = request.correlation_id.clone();
                let query_digest = request.query_digest.clone();
                let response_digest = request.response_digest.clone();
                self.with_store(move |store| {
                    Ok(store.claim_matching_response(&TraceResponseMatch {
                        request_trace_id: &request_trace_id,
                        server_id: &server_id,
                        correlation_id: &correlation_id,
                        query_digest: &query_digest,
                        response_digest: &response_digest,
                        endpoint: None,
                        allow_authority_response: false,
                    })?)
                })
                .await?
            };
            if let Some(anchor) = anchor {
                return Ok(anchor);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::EvidenceUnavailable(
                    "no matching final resolver response event".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn fetch_target_graph(
        &self,
        target: &DnsServerIdentityV2,
        request: EvidenceGraphRequest,
    ) -> Result<Option<QueryEvidenceGraphV2>, AgentError> {
        let service_url = target
            .agent
            .as_ref()
            .and_then(|agent| agent.service_url.as_deref());
        let Some(service_url) = service_url else {
            return Err(AgentError::EvidenceUnavailable(format!(
                "recursive target {} does not publish an Agent URL",
                target.server_id
            )));
        };
        let response = self
            .client
            .post(format!(
                "{}/v2/downstream-evidence-graph",
                service_url.trim_end_matches('/')
            ))
            .bearer_auth(&self.config.peer_api_token)
            .json(&request)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let detail =
                decode_error_body_limited(response, self.config.max_request_body_bytes.min(4_096))
                    .await;
            return Err(AgentError::Downstream(format!(
                "{} graph endpoint returned {}{}",
                target.server_id, status, detail
            )));
        }
        let graph = decode_json_limited(
            response,
            self.config.max_request_body_bytes,
            "downstream evidence graph",
        )
        .await?;
        let policy = match self.config.mode {
            VerificationMode::ControlledStrict => EvidencePolicy::controlled_strict(),
            VerificationMode::PublicHybrid => EvidencePolicy::public_hybrid(),
        };
        EvidenceValidator {
            policy: &policy,
            issuer_keys: &self.issuer_keys,
        }
        .validate_graph(&graph, &request.challenge, unix_time())?;
        if graph.query_digest != request.query_digest
            || graph.response_digest != request.response_digest
            || graph.correlation_id != request.correlation_id
        {
            return Err(AgentError::Downstream(
                "downstream graph DNS digest binding mismatch".into(),
            ));
        }
        Ok(Some(graph))
    }
}

pub fn router(state: AgentState) -> Router {
    let max_concurrent_requests = state.config.max_concurrent_requests;
    let max_request_body_bytes = state.config.max_request_body_bytes;
    Router::new()
        .route("/v2/evidence-graph", post(evidence_graph))
        .route(
            "/v2/downstream-evidence-graph",
            post(downstream_evidence_graph),
        )
        .route("/v2/attest-response", post(attest_response))
        .route("/v2/trace-events", post(ingest_trace_event))
        .route("/v2/trace-events/batch", post(ingest_trace_events))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .with_state(Arc::new(state))
        .layer(DefaultBodyLimit::max(max_request_body_bytes))
        .layer(ConcurrencyLimitLayer::new(max_concurrent_requests))
}

async fn evidence_graph(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(request): Json<EvidenceGraphRequest>,
) -> Result<Json<QueryEvidenceGraphV2>, AgentError> {
    authorize_bearer(
        &headers,
        &state.config.wrapper_api_token,
        "Wrapper evidence API",
    )?;
    state.metrics.graph_requests.fetch_add(1, Ordering::Relaxed);
    match state.build_graph_with_context(&request, true).await {
        Ok(graph) => Ok(Json(graph)),
        Err(error) => {
            state.metrics.graph_failures.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    }
}

async fn downstream_evidence_graph(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(request): Json<EvidenceGraphRequest>,
) -> Result<Json<QueryEvidenceGraphV2>, AgentError> {
    authorize_bearer(&headers, &state.config.peer_api_token, "peer evidence API")?;
    state.metrics.graph_requests.fetch_add(1, Ordering::Relaxed);
    match state.build_graph_with_context(&request, false).await {
        Ok(graph) => Ok(Json(graph)),
        Err(error) => {
            state.metrics.graph_failures.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    }
}

async fn attest_response(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(request): Json<ResponseAttestationRequest>,
) -> Result<Json<TargetResponseAttestationV2>, AgentError> {
    authorize_bearer(
        &headers,
        &state.config.peer_api_token,
        "peer attestation API",
    )?;
    Ok(Json(state.attest_response(&request).await?))
}

async fn ingest_trace_event(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(event): Json<TraceEventV2>,
) -> Result<StatusCode, AgentError> {
    authorize_trace_ingestion(&state, &headers)?;
    validate_trace_event(&event, &state.config.server_id)?;
    state
        .with_store(move |store| {
            store.put_trace_event(&event)?;
            Ok(())
        })
        .await?;
    state
        .metrics
        .trace_events_ingested
        .fetch_add(1, Ordering::Relaxed);
    Ok(StatusCode::NO_CONTENT)
}

async fn ingest_trace_events(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(events): Json<Vec<TraceEventV2>>,
) -> Result<StatusCode, AgentError> {
    authorize_trace_ingestion(&state, &headers)?;
    if events.is_empty() || events.len() > 1_024 {
        return Err(AgentError::InvalidRequest(
            "trace batch must contain 1 to 1024 events".into(),
        ));
    }
    for event in &events {
        validate_trace_event(event, &state.config.server_id)?;
    }
    let event_count = u64::try_from(events.len()).unwrap_or(u64::MAX);
    state
        .with_store(move |store| {
            store.put_trace_events(&events)?;
            Ok(())
        })
        .await?;
    state
        .metrics
        .trace_events_ingested
        .fetch_add(event_count, Ordering::Relaxed);
    Ok(StatusCode::NO_CONTENT)
}

async fn health(State(state): State<Arc<AgentState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "server_id": state.config.server_id,
        "schema_version": QUERY_EVIDENCE_GRAPH_V2
    }))
}

async fn metrics(State(state): State<Arc<AgentState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        format!(
            concat!(
                "# TYPE resolver_identity_agent_graph_requests_total counter\n",
                "resolver_identity_agent_graph_requests_total {}\n",
                "# TYPE resolver_identity_agent_graph_failures_total counter\n",
                "resolver_identity_agent_graph_failures_total {}\n",
                "# TYPE resolver_identity_agent_trace_events_ingested_total counter\n",
                "resolver_identity_agent_trace_events_ingested_total {}\n"
            ),
            state.metrics.graph_requests.load(Ordering::Relaxed),
            state.metrics.graph_failures.load(Ordering::Relaxed),
            state.metrics.trace_events_ingested.load(Ordering::Relaxed)
        ),
    )
}

async fn ready(
    State(state): State<Arc<AgentState>>,
) -> Result<Json<serde_json::Value>, AgentError> {
    state.require_fresh_registry(unix_time()).await?;
    let server_id = state.config.server_id.clone();
    let (generation, identity_record) = state
        .with_store(move |store| Ok((store.cache_generation()?, store.get_identity(&server_id)?)))
        .await?;
    let (identity, registry) = identity_record
        .ok_or_else(|| AgentError::EvidenceUnavailable("local identity is not loaded".into()))?;
    let issuer_key = state
        .issuer_keys
        .get(&identity.issuer, &identity.key_id)
        .ok_or_else(|| AgentError::EvidenceUnavailable("identity issuer is not trusted".into()))?;
    ri_core::verify_ed25519(&identity, issuer_key)?;
    if !identity.active_at(unix_time())
        || registry.resolver_status != "ACTIVE"
        || registry.root_status != "ACTIVE"
        || registry.endpoint_binding_status != "MATCHED"
        || registry.object_hash != ri_core::object_hash(&identity)?
    {
        return Err(AgentError::EvidenceUnavailable(
            "local identity or Registry evidence is not active".into(),
        ));
    }
    let public_key = ri_core::ed25519_public_key_b64(&state.config.private_key_b64)?;
    let agent = identity.agent.as_ref().ok_or_else(|| {
        AgentError::EvidenceUnavailable("local identity does not bind an Agent".into())
    })?;
    if agent.key_id != state.config.key_id
        || agent.public_key != public_key
        || !agent.algorithm.eq_ignore_ascii_case("ed25519")
    {
        return Err(AgentError::EvidenceUnavailable(
            "local Agent key does not match the signed identity".into(),
        ));
    }
    Ok(Json(
        serde_json::json!({"ok": true, "cache_generation": generation}),
    ))
}

fn validate_request(
    trace_id: &str,
    correlation_id: &str,
    challenge: &str,
    query_digest: &str,
    response_digest: &str,
) -> Result<(), AgentError> {
    if trace_id.is_empty() || trace_id.len() > 256 {
        return Err(AgentError::InvalidRequest(
            "trace_id length is invalid".into(),
        ));
    }
    if !is_digest(correlation_id) {
        return Err(AgentError::InvalidRequest(
            "correlation_id must be bytes32 hex".into(),
        ));
    }
    if !(32..=256).contains(&challenge.len()) {
        return Err(AgentError::InvalidRequest(
            "challenge must contain 32 to 256 bytes".into(),
        ));
    }
    if !is_digest(query_digest) || !is_digest(response_digest) {
        return Err(AgentError::InvalidRequest(
            "query and response digests must be bytes32 hex".into(),
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn evidence_node(
    identity: DnsServerIdentityV2,
    registry: RegistryReferenceV2,
    evidence_levels: Vec<EvidenceLevel>,
) -> EvidenceNodeV2 {
    EvidenceNodeV2 {
        identity,
        registry,
        evidence_levels,
        accepted: true,
        reasons: vec![],
    }
}

fn target_correlation(event: &TraceEventV2) -> Result<String, AgentError> {
    event.target_correlation_id.clone().ok_or_else(|| {
        AgentError::EvidenceUnavailable(format!(
            "trace event {} lacks target correlation",
            event.event_id
        ))
    })
}

fn merge_node(
    nodes: &mut HashMap<String, EvidenceNodeV2>,
    node: EvidenceNodeV2,
) -> Result<(), AgentError> {
    if let Some(existing) = nodes.get_mut(&node.identity.server_id) {
        if existing.identity != node.identity || existing.registry != node.registry {
            return Err(AgentError::EvidenceUnavailable(format!(
                "conflicting evidence for {}",
                node.identity.server_id
            )));
        }
        for level in &node.evidence_levels {
            if !existing.evidence_levels.contains(level) {
                existing.evidence_levels.push(*level);
            }
        }
    } else {
        nodes.insert(node.identity.server_id.clone(), node);
    }
    Ok(())
}

fn self_record_endpoint(
    nodes: &HashMap<String, EvidenceNodeV2>,
    server_id: &str,
) -> Result<DnsEndpoint, AgentError> {
    nodes
        .get(server_id)
        .and_then(|node| node.identity.endpoints.first())
        .cloned()
        .ok_or_else(|| AgentError::EvidenceUnavailable("local endpoint is not configured".into()))
}

fn terminal_nodes(
    nodes: &HashMap<String, EvidenceNodeV2>,
    edges: &[ServerHopEvidenceV2],
    entry_server_id: &str,
) -> Vec<String> {
    let sources = edges
        .iter()
        .map(|edge| edge.from_server_id.as_str())
        .collect::<HashSet<_>>();
    let mut terminal = nodes
        .keys()
        .filter(|server_id| server_id.as_str() != entry_server_id)
        .filter(|server_id| !sources.contains(server_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    terminal.sort();
    terminal
}

fn aggregate_dnssec_status(
    edges: &[ServerHopEvidenceV2],
    nodes: &HashMap<String, EvidenceNodeV2>,
    terminal_cache_graphs: &[QueryEvidenceGraphV2],
) -> DnssecStatus {
    let direct_authority = nodes.values().any(|node| node.identity.role.is_authority());
    let cached_authority = terminal_cache_graphs.iter().any(graph_requires_dnssec);
    if !direct_authority && !cached_authority {
        return DnssecStatus::NotApplicable;
    }
    let direct_secure = edges.iter().all(|edge| {
        nodes
            .get(&edge.to_server_id)
            .is_none_or(|node| !node.identity.role.is_authority())
            || nodes.get(&edge.to_server_id).is_some_and(|node| {
                node.evidence_levels
                    .contains(&EvidenceLevel::DnssecValidated)
            })
    });
    let cached_secure = terminal_cache_graphs
        .iter()
        .filter(|graph| graph_requires_dnssec(graph))
        .all(|graph| graph.dnssec_status == DnssecStatus::Secure);
    if direct_secure && cached_secure {
        DnssecStatus::Secure
    } else {
        DnssecStatus::Indeterminate
    }
}

fn graph_requires_dnssec(graph: &QueryEvidenceGraphV2) -> bool {
    graph
        .nodes
        .iter()
        .any(|node| node.identity.role.is_authority())
        || graph
            .cache_provenance
            .as_ref()
            .is_some_and(|provenance| provenance.source_dnssec_required)
        || graph
            .terminal_cache_graphs
            .iter()
            .any(graph_requires_dnssec)
}

async fn decode_json_limited<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
    description: &str,
) -> Result<T, AgentError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(AgentError::Downstream(format!(
            "{description} exceeds the configured response limit"
        )));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(limit),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AgentError::Downstream(format!(
                "{description} exceeds the configured response limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

async fn decode_error_body_limited(response: reqwest::Response, limit: usize) -> String {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return String::new();
        };
        if body.len().saturating_add(chunk.len()) > limit {
            return " (response detail exceeded limit)".into();
        }
        body.extend_from_slice(&chunk);
    }
    let detail = String::from_utf8_lossy(&body);
    if detail.trim().is_empty() {
        String::new()
    } else {
        format!(": {}", detail.trim())
    }
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn validate_trace_event(event: &TraceEventV2, server_id: &str) -> Result<(), AgentError> {
    if event.schema_version != TRACE_EVENT_V2 {
        return Err(AgentError::InvalidRequest(
            "trace event schema is unsupported".into(),
        ));
    }
    if event.event_id.is_empty()
        || event.event_id.len() > 256
        || event.trace_id.is_empty()
        || event.trace_id.len() > 256
        || event.sequence == 0
        || event.observer_server_id != server_id
        || !is_digest(&event.correlation_id)
        || event
            .target_correlation_id
            .as_deref()
            .is_some_and(|correlation| !is_digest(correlation))
        || !is_digest(&event.query_digest)
        || event
            .response_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
        || event
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.is_empty() || reason.len() > 128)
    {
        return Err(AgentError::InvalidRequest(
            "trace event fields are invalid".into(),
        ));
    }
    let now = unix_time();
    if event.observed_at < now - 300 || event.observed_at > now + 5 {
        return Err(AgentError::InvalidRequest(
            "trace event timestamp is outside the ingestion window".into(),
        ));
    }
    if (event.sequence == 1) != (event.kind == TraceEventKind::ClientQuery)
        || (event.sequence == 1 && event.parent_event_id.is_some())
        || (event.sequence > 1
            && event
                .parent_event_id
                .as_deref()
                .is_none_or(|parent| parent.is_empty() || parent.len() > 256))
    {
        return Err(AgentError::InvalidRequest(
            "trace event sequence and parent are inconsistent".into(),
        ));
    }
    match event.kind {
        TraceEventKind::UpstreamQuery => {
            if event.target_endpoint.is_none()
                || event.target_correlation_id.is_none()
                || event.attempt.is_none_or(|attempt| attempt == 0)
                || event.response_digest.is_some()
            {
                return Err(AgentError::InvalidRequest(
                    "upstream query requires endpoint, target correlation and attempt".into(),
                ));
            }
        }
        TraceEventKind::ResolverQuery | TraceEventKind::AuthorityQuery => {
            if event.target_endpoint.is_none()
                || event.target_correlation_id.is_none()
                || event.response_digest.is_none()
            {
                return Err(AgentError::InvalidRequest(
                    "outbound trace event requires endpoint, target correlation and response"
                        .into(),
                ));
            }
        }
        TraceEventKind::UpstreamResponse => {
            if event.target_endpoint.is_none()
                || event.target_correlation_id.is_none()
                || event.attempt.is_none_or(|attempt| attempt == 0)
                || event.response_digest.is_none()
            {
                return Err(AgentError::InvalidRequest(
                    "upstream response requires endpoint, target correlation, attempt and response"
                        .into(),
                ));
            }
        }
        TraceEventKind::ResolverResponse | TraceEventKind::AuthorityResponse => {
            if event.target_endpoint.is_none()
                || event.response_digest.is_none()
                || event.attempt.is_none_or(|attempt| attempt == 0)
            {
                return Err(AgentError::InvalidRequest(
                    "response trace event requires endpoint and response digest".into(),
                ));
            }
        }
        TraceEventKind::CacheHit => {
            if event.response_digest.is_none()
                || event
                    .cache_object_digest
                    .as_deref()
                    .is_none_or(|digest| !is_digest(digest))
                || event.ttl_expires_at.is_none()
                || event
                    .source_graph_digest
                    .as_deref()
                    .is_none_or(|digest| !is_digest(digest))
            {
                return Err(AgentError::InvalidRequest(
                    "cache-hit event requires response, cache object, TTL and source graph digest"
                        .into(),
                ));
            }
        }
        TraceEventKind::UpstreamTimeout
        | TraceEventKind::UpstreamRetry
        | TraceEventKind::TransportSwitch => {
            if event.attempt.is_none_or(|attempt| attempt == 0) || event.failure_reason.is_none() {
                return Err(AgentError::InvalidRequest(
                    "transport event requires attempt and reason".into(),
                ));
            }
        }
        TraceEventKind::ClientResponse => {
            if event.response_digest.is_none()
                || (event.sequence > 0
                    && event
                        .cache_object_digest
                        .as_deref()
                        .is_none_or(|digest| !is_digest(digest)))
            {
                return Err(AgentError::InvalidRequest(
                    "client response requires response and normalized cache object digests".into(),
                ));
            }
        }
        TraceEventKind::ResolutionFailed => {
            if event.failure_reason.is_none() {
                return Err(AgentError::InvalidRequest(
                    "resolution failure requires a reason".into(),
                ));
            }
        }
        TraceEventKind::ClientQuery => {}
    }
    Ok(())
}

fn authorize_trace_ingestion(state: &AgentState, headers: &HeaderMap) -> Result<(), AgentError> {
    authorize_bearer(headers, &state.config.trace_ingest_token, "trace ingestion")
}

fn authorize_bearer(headers: &HeaderMap, token: &str, purpose: &str) -> Result<(), AgentError> {
    let expected = format!("Bearer {token}");
    if token.is_empty()
        || headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|actual| !constant_time_eq(actual.as_bytes(), expected.as_bytes()))
    {
        return Err(AgentError::Unauthorized(format!(
            "{purpose} authorization failed"
        )));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
