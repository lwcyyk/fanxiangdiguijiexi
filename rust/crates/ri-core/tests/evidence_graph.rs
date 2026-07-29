use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use ri_core::evidence::{
    DNS_SERVER_IDENTITY_V2, QUERY_EVIDENCE_GRAPH_V2, SERVER_HOP_EVIDENCE_V2,
    TARGET_RESPONSE_ATTESTATION_V2,
};
use ri_core::{
    AgentBindingV2, CacheProvenanceV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole,
    DnssecStatus, EvidenceLevel, EvidenceNodeV2, EvidencePolicy, EvidenceValidationError,
    EvidenceValidator, IssuerKeyRegistry, QueryEvidenceGraphV2, RegistryReferenceV2,
    ServerHopEvidenceV2, TargetResponseAttestationV2, VerificationMode, ed25519_public_key_b64,
    object_hash, sign_ed25519,
};

const NOW: i64 = 1_800_000_000;
const CHALLENGE: &str = "challenge-with-at-least-32-characters";
const CORRELATION: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const QUERY_DIGEST: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESPONSE_DIGEST: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TestKeys {
    issuer_private: String,
    issuer_public: String,
    r1_private: String,
    root_private: String,
}

impl TestKeys {
    fn new() -> Self {
        Self {
            issuer_private: key(1),
            issuer_public: ed25519_public_key_b64(&key(1)).unwrap(),
            r1_private: key(33),
            root_private: key(65),
        }
    }
}

#[test]
fn controlled_graph_accepts_signed_recursive_and_root_path() {
    let keys = TestKeys::new();
    let graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    validator(&keys, EvidencePolicy::controlled_strict())
        .validate_graph(&graph, CHALLENGE, NOW)
        .unwrap();
}

#[test]
fn controlled_graph_rejects_missing_target_attestation() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.edges[0].target_attestation = None;
    resign_edge_and_graph(&mut graph, &keys.r1_private);
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::PolicyRejected(message))
            if message.contains("lacks target response attestation")
    ));
}

#[test]
fn graph_rejects_challenge_replay() {
    let keys = TestKeys::new();
    let graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict()).validate_graph(
            &graph,
            "a-different-challenge-with-32-characters",
            NOW
        ),
        Err(EvidenceValidationError::InvalidGraph(message)) if message == "challenge mismatch"
    ));
}

#[test]
fn graph_rejects_revoked_registry_node() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.nodes[1].registry.resolver_status = "REVOKED".into();
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::InvalidGraph(message))
            if message.contains("registry evidence mismatch")
    ));
}

#[test]
fn graph_rejects_cycle_even_when_every_edge_is_signed() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    let r1 = graph.nodes[0].identity.clone();
    let root = graph.nodes[1].identity.clone();
    let mut reverse = ServerHopEvidenceV2 {
        schema_version: SERVER_HOP_EVIDENCE_V2.into(),
        edge_id: "root-to-r1".into(),
        trace_id: graph.trace_id.clone(),
        target_correlation_id: CORRELATION.into(),
        challenge: graph.challenge.clone(),
        from_server_id: root.server_id,
        to_server_id: r1.server_id,
        from_endpoint: root.endpoints[0].clone(),
        to_endpoint: r1.endpoints[0].clone(),
        query_digest: graph.query_digest.clone(),
        response_digest: graph.response_digest.clone(),
        observed_at: NOW,
        issued_at: NOW,
        expires_at: NOW + 30,
        accepted: true,
        reasons: vec![],
        registry: graph.nodes[0].registry.clone(),
        target_attestation: Some(signed_target_attestation(
            &graph.nodes[0].identity,
            &keys.r1_private,
        )),
        key_id: "root-agent-key".into(),
        signature: None,
    };
    reverse.signature = Some(sign_ed25519(&reverse, &keys.root_private).unwrap());
    graph.edges.push(reverse);
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());

    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::InvalidGraph(message)) if message.contains("cycle")
    ));
}

#[test]
fn graph_rejects_expired_cache_provenance() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.cache_provenance = Some(CacheProvenanceV2 {
        source_graph_digest: "0xsource".into(),
        source_dnssec_required: true,
        cached_at: NOW - 100,
        dns_ttl_expires_at: NOW - 1,
        identity_expires_at: NOW + 100,
        snapshot_generation: 7,
    });
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::PolicyRejected(message))
            if message == "cache provenance expired"
    ));
}

#[test]
fn graph_rejects_edge_registry_mismatch() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.edges[0].registry.snapshot_generation += 1;
    resign_edge_and_graph(&mut graph, &keys.r1_private);
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::InvalidGraph(message))
            if message.contains("Registry reference differs")
    ));
}

#[test]
fn graph_rejects_edge_less_non_cache_path() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.nodes.truncate(1);
    graph.edges.clear();
    graph.terminal_node_ids = vec![graph.entry_server_id.clone()];
    graph.dnssec_status = DnssecStatus::NotApplicable;
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::PolicyRejected(message))
            if message == "edge-less graph requires cache provenance"
    ));
}

#[test]
fn recursive_terminal_requires_its_signed_cache_graph() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    graph.nodes[1].identity.server_id = "operator/r2".into();
    graph.nodes[1].identity.role = DnsServerRole::Recursive;
    graph.nodes[1].identity.anycast = false;
    graph.nodes[1].identity.anycast_service_id = None;
    graph.nodes[1].identity.signature =
        Some(sign_ed25519(&graph.nodes[1].identity, &keys.issuer_private).unwrap());
    graph.nodes[1].registry = registry(&graph.nodes[1].identity);
    let recursive = graph.nodes[1].clone();
    graph.edges[0].to_server_id = recursive.identity.server_id.clone();
    graph.edges[0].registry = recursive.registry.clone();
    graph.edges[0].target_attestation = Some(signed_target_attestation(
        &recursive.identity,
        &keys.root_private,
    ));
    graph.terminal_node_ids = vec![recursive.identity.server_id.clone()];
    resign_edge_and_graph(&mut graph, &keys.r1_private);

    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&graph, CHALLENGE, NOW),
        Err(EvidenceValidationError::PolicyRejected(message))
            if message.contains("lacks signed cache provenance")
    ));

    let mut cache_graph = QueryEvidenceGraphV2 {
        schema_version: QUERY_EVIDENCE_GRAPH_V2.into(),
        trace_id: graph.trace_id.clone(),
        correlation_id: graph.edges[0].target_correlation_id.clone(),
        challenge: graph.challenge.clone(),
        query_digest: graph.edges[0].query_digest.clone(),
        response_digest: graph.edges[0].response_digest.clone(),
        mode: graph.mode,
        entry_server_id: recursive.identity.server_id.clone(),
        issued_at: NOW,
        expires_at: NOW + 30,
        dnssec_status: DnssecStatus::Secure,
        cache_provenance: Some(CacheProvenanceV2 {
            source_graph_digest:
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            source_dnssec_required: true,
            cached_at: NOW - 1,
            dns_ttl_expires_at: NOW + 30,
            identity_expires_at: NOW + 300,
            snapshot_generation: recursive.registry.snapshot_generation,
        }),
        terminal_cache_graphs: vec![],
        nodes: vec![recursive.clone()],
        edges: vec![],
        terminal_node_ids: vec![recursive.identity.server_id.clone()],
        final_result: true,
        graph_errors: vec![],
        key_id: recursive.identity.agent.as_ref().unwrap().key_id.clone(),
        signature: None,
    };
    cache_graph.signature = Some(sign_ed25519(&cache_graph, &keys.root_private).unwrap());
    graph.terminal_cache_graphs.push(cache_graph);
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());

    let mut downgraded = graph.clone();
    downgraded.dnssec_status = DnssecStatus::NotApplicable;
    downgraded.signature = Some(sign_ed25519(&downgraded, &keys.r1_private).unwrap());
    assert!(matches!(
        validator(&keys, EvidencePolicy::controlled_strict())
            .validate_graph(&downgraded, CHALLENGE, NOW),
        Err(EvidenceValidationError::InvalidGraph(message))
            if message.contains("DNSSEC summary")
    ));

    validator(&keys, EvidencePolicy::controlled_strict())
        .validate_graph(&graph, CHALLENGE, NOW)
        .unwrap();
}

#[test]
fn public_hybrid_accepts_dnssec_root_without_agent() {
    let keys = TestKeys::new();
    let mut graph = signed_graph(&keys, VerificationMode::PublicHybrid, false);
    graph.edges[0].target_attestation = None;
    graph.nodes[1].identity.agent = None;
    graph.nodes[1].identity.signature =
        Some(sign_ed25519(&graph.nodes[1].identity, &keys.issuer_private).unwrap());
    graph.nodes[1].registry.object_hash = object_hash(&graph.nodes[1].identity).unwrap();
    graph.edges[0].registry = graph.nodes[1].registry.clone();
    resign_edge_and_graph(&mut graph, &keys.r1_private);

    validator(&keys, EvidencePolicy::public_hybrid())
        .validate_graph(&graph, CHALLENGE, NOW)
        .unwrap();
}

#[test]
#[ignore = "manual release-mode capacity baseline"]
fn validation_capacity_baseline() {
    let keys = TestKeys::new();
    let graph = signed_graph(&keys, VerificationMode::ControlledStrict, true);
    let validator = validator(&keys, EvidencePolicy::controlled_strict());
    let iterations = 10_000_u32;
    let started = std::time::Instant::now();
    for _ in 0..iterations {
        validator.validate_graph(&graph, CHALLENGE, NOW).unwrap();
    }
    let elapsed = started.elapsed();
    let per_second = f64::from(iterations) / elapsed.as_secs_f64();
    eprintln!("validated {iterations} signed graphs in {elapsed:?} ({per_second:.0} graphs/s)");
}

fn signed_graph(
    keys: &TestKeys,
    mode: VerificationMode,
    controlled_root: bool,
) -> QueryEvidenceGraphV2 {
    let r1 = signed_identity(
        "operator/r1",
        DnsServerRole::Recursive,
        endpoint("192.0.2.53"),
        Some(AgentBindingV2 {
            key_id: "r1-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(&keys.r1_private).unwrap(),
            service_url: Some("https://r1-agent.test".into()),
        }),
        &keys.issuer_private,
    );
    let root = signed_identity(
        "root/a-service",
        DnsServerRole::RootAuthority,
        endpoint("198.41.0.4"),
        Some(AgentBindingV2 {
            key_id: "root-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(&keys.root_private).unwrap(),
            service_url: Some("https://root-agent.test".into()),
        }),
        &keys.issuer_private,
    );
    let r1_registry = registry(&r1);
    let root_registry = registry(&root);
    let mut edge = ServerHopEvidenceV2 {
        schema_version: SERVER_HOP_EVIDENCE_V2.into(),
        edge_id: "r1-to-root".into(),
        trace_id: "trace-01".into(),
        target_correlation_id: CORRELATION.into(),
        challenge: CHALLENGE.into(),
        from_server_id: r1.server_id.clone(),
        to_server_id: root.server_id.clone(),
        from_endpoint: r1.endpoints[0].clone(),
        to_endpoint: root.endpoints[0].clone(),
        query_digest: QUERY_DIGEST.into(),
        response_digest: RESPONSE_DIGEST.into(),
        observed_at: NOW,
        issued_at: NOW,
        expires_at: NOW + 30,
        accepted: true,
        reasons: vec![],
        registry: root_registry.clone(),
        target_attestation: controlled_root
            .then(|| signed_target_attestation(&root, &keys.root_private)),
        key_id: "r1-agent-key".into(),
        signature: None,
    };
    edge.signature = Some(sign_ed25519(&edge, &keys.r1_private).unwrap());

    let root_levels = if controlled_root {
        vec![
            EvidenceLevel::RegistryBound,
            EvidenceLevel::AgentAttested,
            EvidenceLevel::DnssecValidated,
        ]
    } else {
        vec![EvidenceLevel::RegistryBound, EvidenceLevel::DnssecValidated]
    };
    let mut graph = QueryEvidenceGraphV2 {
        schema_version: QUERY_EVIDENCE_GRAPH_V2.into(),
        trace_id: "trace-01".into(),
        correlation_id: CORRELATION.into(),
        challenge: CHALLENGE.into(),
        query_digest: QUERY_DIGEST.into(),
        response_digest: RESPONSE_DIGEST.into(),
        mode,
        entry_server_id: r1.server_id.clone(),
        issued_at: NOW,
        expires_at: NOW + 30,
        dnssec_status: DnssecStatus::Secure,
        cache_provenance: None,
        terminal_cache_graphs: vec![],
        nodes: vec![
            EvidenceNodeV2 {
                identity: r1,
                registry: r1_registry,
                evidence_levels: vec![EvidenceLevel::RegistryBound, EvidenceLevel::AgentAttested],
                accepted: true,
                reasons: vec![],
            },
            EvidenceNodeV2 {
                identity: root,
                registry: root_registry,
                evidence_levels: root_levels,
                accepted: true,
                reasons: vec![],
            },
        ],
        edges: vec![edge],
        terminal_node_ids: vec!["root/a-service".into()],
        final_result: true,
        graph_errors: vec![],
        key_id: "r1-agent-key".into(),
        signature: None,
    };
    graph.signature = Some(sign_ed25519(&graph, &keys.r1_private).unwrap());
    graph
}

fn signed_identity(
    server_id: &str,
    role: DnsServerRole,
    endpoint: DnsEndpoint,
    agent: Option<AgentBindingV2>,
    issuer_private: &str,
) -> DnsServerIdentityV2 {
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
        valid_from: NOW - 3600,
        valid_until: NOW + 3600,
        object_version: 1,
        status: "ACTIVE".into(),
        issuer: "test-issuer".into(),
        key_id: "issuer-key".into(),
        signature: None,
    };
    identity.signature = Some(sign_ed25519(&identity, issuer_private).unwrap());
    identity
}

fn signed_target_attestation(
    target: &DnsServerIdentityV2,
    private_key: &str,
) -> TargetResponseAttestationV2 {
    let mut attestation = TargetResponseAttestationV2 {
        schema_version: TARGET_RESPONSE_ATTESTATION_V2.into(),
        target_server_id: target.server_id.clone(),
        trace_id: "trace-01".into(),
        correlation_id: CORRELATION.into(),
        challenge: CHALLENGE.into(),
        query_digest: QUERY_DIGEST.into(),
        response_digest: RESPONSE_DIGEST.into(),
        endpoint: target.endpoints[0].clone(),
        observed_at: NOW,
        issued_at: NOW,
        expires_at: NOW + 30,
        key_id: target.agent.as_ref().unwrap().key_id.clone(),
        signature: None,
    };
    attestation.signature = Some(sign_ed25519(&attestation, private_key).unwrap());
    attestation
}

fn registry(identity: &DnsServerIdentityV2) -> RegistryReferenceV2 {
    RegistryReferenceV2 {
        chain_id: 31_337,
        contract_address: "0x1111111111111111111111111111111111111111".into(),
        contract_code_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
            .into(),
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

fn validator(keys: &TestKeys, policy: EvidencePolicy) -> EvidenceValidator<'_> {
    let registry = Box::leak(Box::new({
        let mut registry = IssuerKeyRegistry::default();
        registry.insert("test-issuer", "issuer-key", keys.issuer_public.clone());
        registry
    }));
    let policy = Box::leak(Box::new(policy));
    EvidenceValidator {
        policy,
        issuer_keys: registry,
    }
}

fn resign_edge_and_graph(graph: &mut QueryEvidenceGraphV2, r1_private: &str) {
    graph.edges[0].signature = Some(sign_ed25519(&graph.edges[0], r1_private).unwrap());
    graph.signature = Some(sign_ed25519(graph, r1_private).unwrap());
}

fn key(start: u8) -> String {
    STANDARD.encode((start..start + 32).collect::<Vec<_>>())
}
