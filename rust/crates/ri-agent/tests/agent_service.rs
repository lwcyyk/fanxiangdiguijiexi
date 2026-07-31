use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ri_agent::{AgentConfig, AgentState, EvidenceGraphRequest, ResponseAttestationRequest, router};
use ri_core::evidence::{DNS_SERVER_IDENTITY_V2, TRACE_EVENT_V2};
use ri_core::{
    AgentBindingV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole, DnssecStatus,
    IssuerKeyRegistry, RegistryReferenceV2, TraceEventKind, TraceEventV2, VerificationMode,
    ed25519_public_key_b64, object_hash, sign_ed25519,
};
use ri_store::EvidenceStore;
use tower::ServiceExt;

const QUERY_DIGEST: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FINAL_RESPONSE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const AUTH_QUERY: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const AUTH_RESPONSE: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const CHALLENGE: &str = "challenge-with-at-least-32-characters";

#[tokio::test]
async fn hybrid_graph_uses_entire_resolver_trace_not_only_final_digest() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    let now = now();
    fixture
        .store
        .put_trace_event(&event(
            "final",
            "resolver-trace",
            TraceEventKind::ResolverResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            now,
        ))
        .unwrap();
    fixture
        .store
        .put_trace_event(&event(
            "to-root",
            "resolver-trace",
            TraceEventKind::AuthorityQuery,
            "operator/r1",
            Some(endpoint("198.41.0.4")),
            AUTH_QUERY,
            Some(AUTH_RESPONSE),
            now,
        ))
        .unwrap();

    let graph = fixture
        .state
        .build_graph(&EvidenceGraphRequest {
            trace_id: "wrapper-trace".into(),
            correlation_id: trace_correlation("resolver-trace"),
            challenge: CHALLENGE.into(),
            query_digest: QUERY_DIGEST.into(),
            response_digest: FINAL_RESPONSE.into(),
            expected_observed_at: Some(now),
            visited_server_ids: vec![],
        })
        .await
        .unwrap();

    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].query_digest, AUTH_QUERY);
    assert_eq!(graph.edges[0].response_digest, AUTH_RESPONSE);
    assert_eq!(graph.terminal_node_ids, ["root/a"]);
}

#[tokio::test]
async fn strict_graph_fails_closed_without_target_agent() {
    let fixture = fixture(VerificationMode::ControlledStrict);
    let now = now();
    fixture
        .store
        .put_trace_event(&event(
            "final",
            "resolver-trace",
            TraceEventKind::ResolverResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            now,
        ))
        .unwrap();
    fixture
        .store
        .put_trace_event(&event(
            "to-root",
            "resolver-trace",
            TraceEventKind::AuthorityQuery,
            "operator/r1",
            Some(endpoint("198.41.0.4")),
            AUTH_QUERY,
            Some(AUTH_RESPONSE),
            now,
        ))
        .unwrap();

    let error = fixture
        .state
        .build_graph(&EvidenceGraphRequest {
            trace_id: "wrapper-trace".into(),
            correlation_id: trace_correlation("resolver-trace"),
            challenge: CHALLENGE.into(),
            query_digest: QUERY_DIGEST.into(),
            response_digest: FINAL_RESPONSE.into(),
            expected_observed_at: Some(now),
            visited_server_ids: vec![],
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not publish an Agent URL"));
}

#[tokio::test]
async fn cache_hit_requires_source_graph_in_current_registry_generation() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    let timestamp = now() - 1;
    fixture
        .store
        .put_trace_event(&event(
            "source-final",
            "source-trace",
            TraceEventKind::ResolverResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            timestamp,
        ))
        .unwrap();
    fixture
        .store
        .put_trace_event(&event(
            "source-root",
            "source-trace",
            TraceEventKind::AuthorityQuery,
            "operator/r1",
            Some(endpoint("198.41.0.4")),
            AUTH_QUERY,
            Some(AUTH_RESPONSE),
            timestamp,
        ))
        .unwrap();
    let source_graph = fixture
        .state
        .build_graph(&EvidenceGraphRequest {
            trace_id: "source-wrapper-trace".into(),
            correlation_id: trace_correlation("source-trace"),
            challenge: CHALLENGE.into(),
            query_digest: QUERY_DIGEST.into(),
            response_digest: FINAL_RESPONSE.into(),
            expected_observed_at: Some(timestamp),
            visited_server_ids: vec![],
        })
        .await
        .unwrap();
    let source_digest = object_hash(&source_graph).unwrap();

    let timestamp = now();
    fixture
        .store
        .put_trace_event(&event(
            "cached-final",
            "cached-trace",
            TraceEventKind::ResolverResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            timestamp,
        ))
        .unwrap();
    let mut cache_hit = event(
        "cached-hit",
        "cached-trace",
        TraceEventKind::CacheHit,
        "operator/r1",
        Some(endpoint("192.0.2.53")),
        QUERY_DIGEST,
        Some(FINAL_RESPONSE),
        timestamp,
    );
    fixture.store.put_trace_event(&cache_hit).unwrap();
    let request = EvidenceGraphRequest {
        trace_id: "cached-wrapper-trace".into(),
        correlation_id: trace_correlation("cached-trace"),
        challenge: "another-challenge-with-at-least-32-characters".into(),
        query_digest: QUERY_DIGEST.into(),
        response_digest: FINAL_RESPONSE.into(),
        expected_observed_at: Some(timestamp),
        visited_server_ids: vec![],
    };
    let error = fixture.state.build_graph(&request).await.unwrap_err();
    assert!(error.to_string().contains("source graph digest"));

    cache_hit.event_id = "cached-hit-valid".into();
    cache_hit.source_graph_digest = Some(source_digest);
    fixture.store.put_trace_event(&cache_hit).unwrap();
    let graph = fixture.state.build_graph(&request).await.unwrap();

    assert!(graph.edges.is_empty());
    assert_eq!(graph.terminal_node_ids, ["operator/r1"]);
    assert!(graph.cache_provenance.is_some());
}

#[tokio::test]
async fn recursive_agent_graph_merges_r1_r2_and_root() {
    let issuer_private = key(1);
    let r1_private = key(33);
    let r2_private = key(65);
    let root = identity(
        "root/a",
        DnsServerRole::RootAuthority,
        endpoint("198.41.0.4"),
        None,
        &issuer_private,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service_url = format!("http://{}", listener.local_addr().unwrap());
    let r2 = identity(
        "operator/r2",
        DnsServerRole::Forwarder,
        endpoint("192.0.2.54"),
        Some(AgentBindingV2 {
            key_id: "r2-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(&r2_private).unwrap(),
            service_url: Some(service_url),
        }),
        &issuer_private,
    );
    let r1 = identity(
        "operator/r1",
        DnsServerRole::Recursive,
        endpoint("192.0.2.53"),
        Some(AgentBindingV2 {
            key_id: "r1-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(&r1_private).unwrap(),
            service_url: Some("http://127.0.0.1:9".into()),
        }),
        &issuer_private,
    );
    let mut issuer_keys = IssuerKeyRegistry::default();
    issuer_keys.insert(
        "test-issuer",
        "issuer-key",
        ed25519_public_key_b64(&issuer_private).unwrap(),
    );

    let r2_directory = tempfile::tempdir().unwrap();
    let r2_store = EvidenceStore::open(r2_directory.path().join("r2.db")).unwrap();
    r2_store.put_identity(&r2, &registry(&r2)).unwrap();
    r2_store.put_identity(&root, &registry(&root)).unwrap();
    r2_store.mark_registry_sync_success(now()).unwrap();
    let timestamp = now();
    r2_store
        .put_trace_event(&event(
            "r2-final",
            "r2-resolver-trace",
            TraceEventKind::ResolverResponse,
            "operator/r2",
            Some(endpoint("192.0.2.54")),
            AUTH_QUERY,
            Some(AUTH_RESPONSE),
            timestamp,
        ))
        .unwrap();
    r2_store
        .put_trace_event(&event(
            "r2-root",
            "r2-resolver-trace",
            TraceEventKind::AuthorityQuery,
            "operator/r2",
            Some(endpoint("198.41.0.4")),
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            timestamp,
        ))
        .unwrap();
    let r2_state = AgentState::new(
        AgentConfig {
            server_id: "operator/r2".into(),
            private_key_b64: r2_private,
            key_id: "r2-agent-key".into(),
            mode: VerificationMode::PublicHybrid,
            max_age_seconds: 30,
            trace_lookback_seconds: 10,
            trace_wait_millis: 10,
            max_cache_ttl_seconds: 3_600,
            registry_max_staleness_seconds: 15,
            trace_ingest_token: "trace-token-for-r2-with-32-bytes".into(),
            wrapper_api_token: "wrapper-token-for-r2".into(),
            peer_api_token: "shared-peer-token".into(),
            max_concurrent_requests: 32,
            max_request_body_bytes: 1_048_576,
        },
        r2_store,
        issuer_keys.clone(),
        reqwest::Client::new(),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router(r2_state)).await.unwrap();
    });

    let r1_directory = tempfile::tempdir().unwrap();
    let r1_store = EvidenceStore::open(r1_directory.path().join("r1.db")).unwrap();
    r1_store.put_identity(&r1, &registry(&r1)).unwrap();
    r1_store.put_identity(&r2, &registry(&r2)).unwrap();
    r1_store.mark_registry_sync_success(now()).unwrap();
    r1_store
        .put_trace_event(&event(
            "r1-final",
            "r1-resolver-trace",
            TraceEventKind::ResolverResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            timestamp,
        ))
        .unwrap();
    let mut r1_to_r2 = event(
        "r1-r2",
        "r1-resolver-trace",
        TraceEventKind::ResolverQuery,
        "operator/r1",
        Some(endpoint("192.0.2.54")),
        AUTH_QUERY,
        Some(AUTH_RESPONSE),
        timestamp,
    );
    r1_to_r2.target_correlation_id = Some(trace_correlation("r2-resolver-trace"));
    r1_store.put_trace_event(&r1_to_r2).unwrap();
    let r1_state = AgentState::new(
        AgentConfig {
            server_id: "operator/r1".into(),
            private_key_b64: r1_private,
            key_id: "r1-agent-key".into(),
            mode: VerificationMode::PublicHybrid,
            max_age_seconds: 30,
            trace_lookback_seconds: 10,
            trace_wait_millis: 10,
            max_cache_ttl_seconds: 3_600,
            registry_max_staleness_seconds: 15,
            trace_ingest_token: "trace-token-for-r1-with-32-bytes".into(),
            wrapper_api_token: "wrapper-token-for-r1".into(),
            peer_api_token: "shared-peer-token".into(),
            max_concurrent_requests: 32,
            max_request_body_bytes: 1_048_576,
        },
        r1_store,
        issuer_keys,
        reqwest::Client::new(),
    );
    let graph = r1_state
        .build_graph(&EvidenceGraphRequest {
            trace_id: "recursive-wrapper-trace".into(),
            correlation_id: trace_correlation("r1-resolver-trace"),
            challenge: CHALLENGE.into(),
            query_digest: QUERY_DIGEST.into(),
            response_digest: FINAL_RESPONSE.into(),
            expected_observed_at: Some(timestamp),
            visited_server_ids: vec![],
        })
        .await
        .unwrap();
    server.abort();

    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.edges.len(), 2);
    assert!(graph.edges.iter().any(|edge| {
        edge.from_server_id == "operator/r1" && edge.to_server_id == "operator/r2"
    }));
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| { edge.from_server_id == "operator/r2" && edge.to_server_id == "root/a" })
    );
    assert_eq!(graph.terminal_node_ids, ["root/a"]);
}

#[tokio::test]
async fn response_attestation_uses_local_observation_time() {
    let fixture = fixture(VerificationMode::ControlledStrict);
    let observed_at = now() - 1;
    fixture
        .store
        .put_trace_event(&event(
            "authority-response",
            "authority-trace",
            TraceEventKind::AuthorityResponse,
            "operator/r1",
            Some(endpoint("192.0.2.53")),
            QUERY_DIGEST,
            Some(FINAL_RESPONSE),
            observed_at,
        ))
        .unwrap();

    let attestation = fixture
        .state
        .attest_response(&ResponseAttestationRequest {
            trace_id: "wrapper-trace".into(),
            correlation_id: trace_correlation("authority-trace"),
            challenge: CHALLENGE.into(),
            query_digest: QUERY_DIGEST.into(),
            response_digest: FINAL_RESPONSE.into(),
            endpoint: endpoint("192.0.2.53"),
            observed_at: observed_at - 1,
        })
        .await
        .unwrap();
    assert_eq!(attestation.observed_at, observed_at);
}

#[tokio::test]
async fn trace_ingestion_requires_token_and_local_observer() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    let app = router(fixture.state);
    let mut trace = event(
        "ingested",
        "resolver-trace",
        TraceEventKind::ResolverQuery,
        "operator/r1",
        Some(endpoint("198.41.0.4")),
        AUTH_QUERY,
        Some(AUTH_RESPONSE),
        now(),
    );
    let unauthorized = app
        .clone()
        .oneshot(json_request("/v2/trace-events", &trace, None))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    trace.observer_server_id = "operator/other".into();
    let wrong_observer = app
        .clone()
        .oneshot(json_request(
            "/v2/trace-events",
            &trace,
            Some("Bearer trace-token"),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_observer.status(), StatusCode::UNPROCESSABLE_ENTITY);

    trace.observer_server_id = "operator/r1".into();
    trace.target_correlation_id = None;
    let incomplete = app
        .clone()
        .oneshot(json_request(
            "/v2/trace-events",
            &trace,
            Some("Bearer trace-token"),
        ))
        .await
        .unwrap();
    assert_eq!(incomplete.status(), StatusCode::UNPROCESSABLE_ENTITY);

    trace.target_correlation_id = Some(ri_core::sha256_hex("target:ingested"));
    let accepted = app
        .oneshot(json_request(
            "/v2/trace-events",
            &trace,
            Some("Bearer trace-token"),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn evidence_endpoints_enforce_caller_role_token() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    let app = router(fixture.state);
    let request = EvidenceGraphRequest {
        trace_id: "wrapper-request".into(),
        correlation_id: trace_correlation("missing-trace"),
        challenge: CHALLENGE.into(),
        query_digest: QUERY_DIGEST.into(),
        response_digest: FINAL_RESPONSE.into(),
        expected_observed_at: Some(now()),
        visited_server_ids: vec![],
    };

    let peer_on_wrapper_endpoint = app
        .clone()
        .oneshot(json_request(
            "/v2/evidence-graph",
            &request,
            Some("Bearer peer-token"),
        ))
        .await
        .unwrap();
    assert_eq!(peer_on_wrapper_endpoint.status(), StatusCode::UNAUTHORIZED);

    let wrapper_on_peer_endpoint = app
        .clone()
        .oneshot(json_request(
            "/v2/downstream-evidence-graph",
            &request,
            Some("Bearer wrapper-token"),
        ))
        .await
        .unwrap();
    assert_eq!(wrapper_on_peer_endpoint.status(), StatusCode::UNAUTHORIZED);

    let authorized_peer = app
        .oneshot(json_request(
            "/v2/downstream-evidence-graph",
            &request,
            Some("Bearer peer-token"),
        ))
        .await
        .unwrap();
    assert_eq!(authorized_peer.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn readiness_checks_private_key_identity_and_registry_binding() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    let response = router(fixture.state)
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn readiness_fails_when_registry_sync_is_stale() {
    let fixture = fixture(VerificationMode::PublicHybrid);
    fixture
        .store
        .mark_registry_sync_success(now() - 60)
        .unwrap();
    let response = router(fixture.state)
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

struct Fixture {
    state: AgentState,
    store: EvidenceStore,
}

fn fixture(mode: VerificationMode) -> Fixture {
    let directory = tempfile::tempdir().unwrap().keep();
    let store = EvidenceStore::open(directory.join("agent.db")).unwrap();
    let issuer_private = key(1);
    let agent_private = key(33);
    let r1 = identity(
        "operator/r1",
        DnsServerRole::Recursive,
        endpoint("192.0.2.53"),
        Some(AgentBindingV2 {
            key_id: "r1-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(&agent_private).unwrap(),
            service_url: Some("http://127.0.0.1:9".into()),
        }),
        &issuer_private,
    );
    let root = identity(
        "root/a",
        DnsServerRole::RootAuthority,
        endpoint("198.41.0.4"),
        None,
        &issuer_private,
    );
    store.put_identity(&r1, &registry(&r1)).unwrap();
    store.put_identity(&root, &registry(&root)).unwrap();
    store.mark_registry_sync_success(now()).unwrap();
    let mut issuer_keys = IssuerKeyRegistry::default();
    issuer_keys.insert(
        "test-issuer",
        "issuer-key",
        ed25519_public_key_b64(&issuer_private).unwrap(),
    );
    let state = AgentState::new(
        AgentConfig {
            server_id: "operator/r1".into(),
            private_key_b64: agent_private,
            key_id: "r1-agent-key".into(),
            mode,
            max_age_seconds: 30,
            trace_lookback_seconds: 10,
            trace_wait_millis: 10,
            max_cache_ttl_seconds: 3_600,
            registry_max_staleness_seconds: 15,
            trace_ingest_token: "trace-token".into(),
            wrapper_api_token: "wrapper-token".into(),
            peer_api_token: "peer-token".into(),
            max_concurrent_requests: 32,
            max_request_body_bytes: 1_048_576,
        },
        store.clone(),
        issuer_keys,
        reqwest::Client::new(),
    );
    Fixture { state, store }
}

fn identity(
    server_id: &str,
    role: DnsServerRole,
    endpoint: DnsEndpoint,
    agent: Option<AgentBindingV2>,
    issuer_private: &str,
) -> DnsServerIdentityV2 {
    let timestamp = now();
    let mut identity = DnsServerIdentityV2 {
        schema_version: DNS_SERVER_IDENTITY_V2.into(),
        server_id: server_id.into(),
        operator_id: "test-operator".into(),
        role,
        endpoints: vec![endpoint],
        anycast: role == DnsServerRole::RootAuthority,
        anycast_service_id: (role == DnsServerRole::RootAuthority)
            .then(|| "a.root-servers.net".into()),
        agent,
        valid_from: timestamp - 60,
        valid_until: timestamp + 3600,
        object_version: 1,
        status: "ACTIVE".into(),
        issuer: "test-issuer".into(),
        key_id: "issuer-key".into(),
        signature: None,
    };
    identity.signature = Some(sign_ed25519(&identity, issuer_private).unwrap());
    identity
}

fn registry(identity: &DnsServerIdentityV2) -> RegistryReferenceV2 {
    RegistryReferenceV2 {
        chain_adapter: "evm".into(),
        chain_identity: "eip155:31337".into(),
        registry_locator: "evm:0x1111111111111111111111111111111111111111".into(),
        registry_schema_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
            .into(),
        evm_chain_id: Some(31_337),
        evm_contract_address: Some("0x1111111111111111111111111111111111111111".into()),
        evm_runtime_code_hash: Some(
            "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
        ),
        finalized_block: 100,
        finalized_block_hash: "0x3333333333333333333333333333333333333333333333333333333333333333"
            .into(),
        state_root: "0x4444444444444444444444444444444444444444444444444444444444444444".into(),
        object_hash: object_hash(identity).unwrap(),
        object_version: identity.object_version,
        resolver_status: "ACTIVE".into(),
        root_status: "ACTIVE".into(),
        endpoint_binding_status: "MATCHED".into(),
        snapshot_generation: 7,
    }
}

#[allow(clippy::too_many_arguments)]
fn event(
    event_id: &str,
    trace_id: &str,
    kind: TraceEventKind,
    observer: &str,
    target_endpoint: Option<DnsEndpoint>,
    query_digest: &str,
    response_digest: Option<&str>,
    observed_at: i64,
) -> TraceEventV2 {
    TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: event_id.into(),
        trace_id: trace_id.into(),
        correlation_id: trace_correlation(trace_id),
        parent_event_id: None,
        kind,
        observer_server_id: observer.into(),
        target_server_id: None,
        target_endpoint,
        target_correlation_id: Some(ri_core::sha256_hex(format!("target:{event_id}"))),
        query_digest: query_digest.into(),
        response_digest: response_digest.map(Into::into),
        observed_at,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: Some(observed_at + 60),
        source_graph_digest: None,
    }
}

fn trace_correlation(trace_id: &str) -> String {
    ri_core::sha256_hex(format!("trace:{trace_id}"))
}

fn endpoint(ip: &str) -> DnsEndpoint {
    DnsEndpoint {
        endpoint_id: None,
        ip: Some(ip.into()),
        port: Some(53),
        transport: "udp".into(),
        uri: None,
        server_name: None,
        alpn: vec![],
    }
}

fn json_request<T: serde::Serialize>(
    path: &str,
    value: &T,
    authorization: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder
        .body(Body::from(serde_json::to_vec(value).unwrap()))
        .unwrap()
}

fn key(start: u8) -> String {
    STANDARD.encode((start..start + 32).collect::<Vec<_>>())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
