use ri_core::evidence::{DNS_SERVER_IDENTITY_V2, TRACE_EVENT_V2};
use ri_core::{
    AgentBindingV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole, DnssecStatus,
    RegistryReferenceV2, TraceEventKind, TraceEventV2, ed25519_public_key_b64, object_hash,
    sign_ed25519,
};
use ri_store::{EvidenceStore, TraceResponseMatch};

const PRIVATE_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[test]
fn stores_identity_endpoint_lookup_and_trace_events() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let mut identity = DnsServerIdentityV2 {
        schema_version: DNS_SERVER_IDENTITY_V2.into(),
        server_id: "operator/r1".into(),
        operator_id: "operator".into(),
        role: DnsServerRole::Recursive,
        endpoints: vec![endpoint("192.0.2.53")],
        anycast: false,
        anycast_service_id: None,
        agent: Some(AgentBindingV2 {
            key_id: "agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: ed25519_public_key_b64(PRIVATE_KEY).unwrap(),
            service_url: Some("https://agent-r1.test".into()),
        }),
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        object_version: 1,
        status: "ACTIVE".into(),
        issuer: "issuer".into(),
        key_id: "issuer-key".into(),
        signature: None,
    };
    identity.signature = Some(sign_ed25519(&identity, PRIVATE_KEY).unwrap());
    let registry = registry(&identity, 1);

    store.put_identity(&identity, &registry).unwrap();
    let (stored, _) = store.get_identity("operator/r1").unwrap().unwrap();
    assert_eq!(stored, identity);
    let (looked_up, _) = store
        .lookup_identity(&endpoint("192.0.2.53"))
        .unwrap()
        .unwrap();
    assert_eq!(looked_up.server_id, "operator/r1");

    let event = TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: "event-1".into(),
        trace_id: "trace-1".into(),
        correlation_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        parent_event_id: None,
        kind: TraceEventKind::ResolverQuery,
        observer_server_id: "operator/r1".into(),
        target_server_id: Some("root/a".into()),
        target_endpoint: Some(endpoint("198.41.0.4")),
        target_correlation_id: Some(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ),
        query_digest: "0xquery".into(),
        response_digest: Some("0xresponse".into()),
        observed_at: 1_800_000_000,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: Some(1_800_000_300),
        source_graph_digest: None,
    };
    store.put_trace_event(&event).unwrap();
    store.put_trace_event(&event).unwrap();
    assert_eq!(store.trace_events("trace-1").unwrap(), vec![event]);
    let mut conflict = store.trace_events("trace-1").unwrap().remove(0);
    conflict.response_digest = Some("0xconflict".into());
    assert!(
        store
            .put_trace_event(&conflict)
            .unwrap_err()
            .to_string()
            .contains("immutable")
    );
    assert_eq!(store.purge_trace_events(1_800_000_001).unwrap(), 1);
    assert!(store.trace_events("trace-1").unwrap().is_empty());
}

#[test]
fn registry_generation_invalidates_cached_graphs() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    assert_eq!(store.cache_generation().unwrap(), 0);
    let identity = unsigned_identity();
    store
        .put_identity(&identity, &registry(&identity, 0))
        .unwrap();
    assert_eq!(store.cache_generation().unwrap(), 1);
    store
        .put_registry_snapshot("registry", &registry(&identity, 9))
        .unwrap();
    assert_eq!(store.cache_generation().unwrap(), 1);

    let mut newer_proof = registry(&identity, 10);
    newer_proof.finalized_block = 101;
    newer_proof.finalized_block_hash =
        "0x5555555555555555555555555555555555555555555555555555555555555555".into();
    store.put_identity(&identity, &newer_proof).unwrap();
    assert_eq!(store.cache_generation().unwrap(), 1);

    let mut changed_state = newer_proof;
    changed_state.endpoint_binding_status = "MISMATCH".into();
    store.put_identity(&identity, &changed_state).unwrap();
    assert_eq!(store.cache_generation().unwrap(), 2);
    assert_eq!(store.invalidate_all().unwrap(), 3);
    assert_eq!(store.registry_last_success_epoch().unwrap(), 0);
    store.mark_registry_sync_success(1_800_000_000).unwrap();
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
}

#[test]
fn registered_query_context_only_claims_new_trace_events_once() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let correlation = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let query = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let response = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    store
        .put_trace_event(&response_event("old", correlation, query, response))
        .unwrap();
    store
        .register_query_context(
            "request-1",
            correlation,
            query,
            1_800_000_000,
            1_800_000_100,
        )
        .unwrap();
    assert!(
        store
            .claim_registered_trace_anchor(
                "request-1",
                "operator/r1",
                correlation,
                query,
                response,
                1_800_000_000,
            )
            .unwrap()
            .is_none()
    );

    let mut delayed = response_event("delayed-old", correlation, query, response);
    delayed.observed_at = 1_799_999_999;
    store.put_trace_event(&delayed).unwrap();
    assert!(
        store
            .claim_registered_trace_anchor(
                "request-1",
                "operator/r1",
                correlation,
                query,
                response,
                1_800_000_000,
            )
            .unwrap()
            .is_none()
    );

    store
        .put_trace_event(&response_event("new", correlation, query, response))
        .unwrap();
    let claimed = store
        .claim_registered_trace_anchor(
            "request-1",
            "operator/r1",
            correlation,
            query,
            response,
            1_800_000_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(claimed.event_id, "new");
    let claimed_again = store
        .claim_registered_trace_anchor(
            "request-1",
            "operator/r1",
            correlation,
            query,
            response,
            1_800_000_000,
        )
        .unwrap_err();
    assert!(claimed_again.to_string().contains("already been consumed"));

    store
        .register_query_context(
            "request-2",
            correlation,
            query,
            1_800_000_000,
            1_800_000_100,
        )
        .unwrap();
    assert!(
        store
            .claim_registered_trace_anchor(
                "request-2",
                "operator/r1",
                correlation,
                query,
                response,
                1_800_000_000,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn response_claim_requires_all_expected_endpoint_fields() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let correlation = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let query = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let response = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut event = response_event("partial-endpoint", correlation, query, response);
    event.kind = TraceEventKind::AuthorityResponse;
    event.target_endpoint = Some(endpoint("192.0.2.53"));
    store.put_trace_event(&event).unwrap();

    let mut expected = endpoint("192.0.2.53");
    expected.server_name = Some("authority.example".into());
    assert!(
        store
            .claim_matching_response(&TraceResponseMatch {
                request_trace_id: "request-endpoint",
                server_id: "operator/r1",
                correlation_id: correlation,
                query_digest: query,
                response_digest: response,
                endpoint: Some(&expected),
                allow_authority_response: true,
                not_before: 1_799_999_999,
                not_after: 1_800_000_001,
            })
            .unwrap()
            .is_none()
    );
}

#[test]
fn registry_snapshot_rejects_finalized_chain_rollback_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let identity = unsigned_identity();
    let reference = registry(&identity, 100);
    store
        .apply_registry_snapshot(&[(identity.clone(), reference.clone())], 1_800_000_000)
        .unwrap();
    assert_eq!(
        store
            .registry_checkpoint()
            .unwrap()
            .unwrap()
            .finalized_block,
        100
    );

    let mut rollback = reference.clone();
    rollback.finalized_block = 99;
    rollback.snapshot_generation = 99;
    assert!(
        store
            .apply_registry_snapshot(&[(identity.clone(), rollback)], 1_800_000_001)
            .unwrap_err()
            .to_string()
            .contains("rollback")
    );
    let stored = store.get_identity(&identity.server_id).unwrap().unwrap();
    assert_eq!(stored.1.finalized_block, 100);
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);

    let mut conflicting_hash = reference;
    conflicting_hash.finalized_block_hash =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(
        store
            .apply_registry_snapshot(&[(identity, conflicting_hash)], 1_800_000_002,)
            .unwrap_err()
            .to_string()
            .contains("hash changed")
    );
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
}

fn response_event(
    event_id: &str,
    correlation_id: &str,
    query_digest: &str,
    response_digest: &str,
) -> TraceEventV2 {
    TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: event_id.into(),
        trace_id: format!("resolver-{event_id}"),
        correlation_id: correlation_id.into(),
        parent_event_id: None,
        kind: TraceEventKind::ResolverResponse,
        observer_server_id: "operator/r1".into(),
        target_server_id: None,
        target_endpoint: None,
        target_correlation_id: None,
        query_digest: query_digest.into(),
        response_digest: Some(response_digest.into()),
        observed_at: 1_800_000_000,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: None,
        source_graph_digest: None,
    }
}

fn unsigned_identity() -> DnsServerIdentityV2 {
    let mut identity = DnsServerIdentityV2 {
        schema_version: DNS_SERVER_IDENTITY_V2.into(),
        server_id: "operator/r1".into(),
        operator_id: "operator".into(),
        role: DnsServerRole::Recursive,
        endpoints: vec![endpoint("192.0.2.53")],
        anycast: false,
        anycast_service_id: None,
        agent: None,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        object_version: 1,
        status: "ACTIVE".into(),
        issuer: "issuer".into(),
        key_id: "issuer-key".into(),
        signature: None,
    };
    identity.signature = Some(sign_ed25519(&identity, PRIVATE_KEY).unwrap());
    identity
}

fn registry(identity: &DnsServerIdentityV2, generation: u64) -> RegistryReferenceV2 {
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
        snapshot_generation: generation,
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
