use ri_core::evidence::{DNS_SERVER_IDENTITY_V2, TRACE_EVENT_V2};
use ri_core::{
    AgentBindingV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole, DnssecStatus,
    RegistryAdapterMetadataV2, RegistryFinalityTypeV2, RegistryReferenceV2, TraceEventKind,
    TraceEventV2, ed25519_public_key_b64, object_hash, sign_ed25519,
};
use ri_store::{EvidenceStore, TraceResponseMatch};
use rusqlite::{Connection, params};

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
        sequence: 0,
        correlation_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        parent_event_id: None,
        kind: TraceEventKind::ResolverQuery,
        observer_server_id: "operator/r1".into(),
        target_server_id: Some("root/a".into()),
        target_endpoint: Some(endpoint("198.41.0.4")),
        target_correlation_id: Some(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ),
        attempt: None,
        query_digest: "0xquery".into(),
        response_digest: Some("0xresponse".into()),
        cache_object_digest: None,
        observed_at: 1_800_000_000,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: Some(1_800_000_300),
        source_graph_digest: None,
        failure_reason: None,
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
    newer_proof.checkpoint_height = 101;
    newer_proof.checkpoint_hash =
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
fn registered_query_context_uses_row_boundary_not_time_window_and_claims_once() {
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
    assert_eq!(claimed.event_id, "delayed-old");
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
    store
        .put_trace_event(&response_event("new", correlation, query, response))
        .unwrap();
    let claimed = store
        .claim_registered_trace_anchor(
            "request-2",
            "operator/r1",
            correlation,
            query,
            response,
            1_800_000_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(claimed.event_id, "new");

    store
        .register_query_context(
            "request-3",
            correlation,
            query,
            1_800_000_000,
            1_800_000_100,
        )
        .unwrap();
    assert!(
        store
            .claim_registered_trace_anchor(
                "request-3",
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
fn production_trace_events_are_immutable_ordered_and_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let first = production_event(1, TraceEventKind::ClientQuery, None);
    store.put_trace_event(&first).unwrap();

    let out_of_order = production_event(3, TraceEventKind::ClientResponse, Some("event-1"));
    assert!(
        store
            .put_trace_event(&out_of_order)
            .unwrap_err()
            .to_string()
            .contains("out of order")
    );

    let terminal = production_event(2, TraceEventKind::ClientResponse, Some("event-1"));
    store.put_trace_event(&terminal).unwrap();
    let mut conflict = terminal.clone();
    conflict.response_digest =
        Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into());
    assert!(
        store
            .put_trace_event(&conflict)
            .unwrap_err()
            .to_string()
            .contains("immutable")
    );

    let after_terminal = production_event(3, TraceEventKind::ClientResponse, Some("event-2"));
    assert!(
        store
            .put_trace_event(&after_terminal)
            .unwrap_err()
            .to_string()
            .contains("terminal")
    );
    assert_eq!(store.trace_events("production-trace").unwrap().len(), 2);
}

#[test]
fn concurrent_trace_writers_do_not_lose_events_or_report_database_locks() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    std::thread::scope(|scope| {
        for worker in 0..16 {
            let store = store.clone();
            scope.spawn(move || {
                for index in 0..16 {
                    let id = format!("worker-{worker}-event-{index}");
                    let correlation = format!("0x{worker:02x}{index:02x}{:060x}", 0);
                    store
                        .put_trace_event(&response_event(
                            &id,
                            &correlation,
                            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        ))
                        .unwrap();
                }
            });
        }
    });
    let connection = Connection::open(directory.path().join("evidence.db")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM ri_v2_trace_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        256
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
    let generation = store.cache_generation().unwrap();
    assert_eq!(
        store
            .registry_checkpoint()
            .unwrap()
            .unwrap()
            .finalized_block,
        100
    );

    let mut rollback = reference.clone();
    rollback.checkpoint_height = 99;
    rollback.snapshot_generation = 99;
    assert!(
        store
            .apply_registry_snapshot(&[(identity.clone(), rollback)], 1_800_000_001)
            .unwrap_err()
            .to_string()
            .contains("rollback")
    );
    let stored = store.get_identity(&identity.server_id).unwrap().unwrap();
    assert_eq!(stored.1.checkpoint_height, 100);
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
    assert_eq!(store.cache_generation().unwrap(), generation);

    let mut old_generation = reference.clone();
    old_generation.snapshot_generation = 99;
    assert!(
        store
            .apply_registry_snapshot(&[(identity.clone(), old_generation)], 1_800_000_001,)
            .unwrap_err()
            .to_string()
            .contains("generation rollback")
    );
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
    assert_eq!(store.cache_generation().unwrap(), generation);

    let mut conflicting_hash = reference;
    conflicting_hash.checkpoint_hash =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(
        store
            .apply_registry_snapshot(&[(identity, conflicting_hash)], 1_800_000_002,)
            .unwrap_err()
            .to_string()
            .contains("hash changed")
    );
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
    assert_eq!(store.cache_generation().unwrap(), generation);
}

#[test]
fn registry_snapshot_rejects_adapter_target_change() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path().join("evidence.db")).unwrap();
    let identity = unsigned_identity();
    let reference = registry(&identity, 100);
    store
        .apply_registry_snapshot(&[(identity.clone(), reference.clone())], 1_800_000_000)
        .unwrap();

    let generation = store.cache_generation().unwrap();
    let mutations = [
        ("chain identity", {
            let mut value = reference.clone();
            value.chain_identity = "eip155:1".into();
            value
        }),
        ("Registry locator", {
            let mut value = reference.clone();
            value.registry_locator = "evm:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
            value
        }),
        ("schema hash", {
            let mut value = reference.clone();
            value.registry_schema_hash =
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
            value
        }),
        ("adapter metadata", {
            let mut value = reference;
            value.adapter_metadata = RegistryAdapterMetadataV2::Evm {
                chain_id: 1,
                contract_address: "0x1111111111111111111111111111111111111111".into(),
                runtime_code_hash:
                    "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            };
            value
        }),
    ];
    for (name, changed) in mutations {
        let error = store
            .apply_registry_snapshot(&[(identity.clone(), changed)], 1_800_000_001)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target changed"), "{name}: {error}");
    }
    assert_eq!(store.registry_last_success_epoch().unwrap(), 1_800_000_000);
    assert_eq!(store.cache_generation().unwrap(), generation);
}

#[test]
fn schema_v2_evm_snapshot_migrates_without_data_loss() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evidence.db");
    let identity = unsigned_identity();
    let old_reference = serde_json::json!({
        "chain_id": 31337,
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_code_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "finalized_block": 100,
        "finalized_block_hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "state_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
        "object_hash": object_hash(&identity).unwrap(),
        "object_version": 1,
        "resolver_status": "ACTIVE",
        "root_status": "ACTIVE",
        "endpoint_binding_status": "MATCHED",
        "snapshot_generation": 7
    })
    .to_string();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            r#"
            CREATE TABLE ri_v2_meta (
              meta_key TEXT PRIMARY KEY,
              meta_value TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE ri_v2_identities (
              server_id TEXT PRIMARY KEY,
              identity_json TEXT NOT NULL,
              identity_hash TEXT NOT NULL,
              object_version INTEGER NOT NULL,
              status TEXT NOT NULL,
              valid_until INTEGER NOT NULL,
              registry_json TEXT NOT NULL,
              snapshot_generation INTEGER NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE ri_v2_registry_snapshot (
              snapshot_key TEXT PRIMARY KEY,
              chain_id INTEGER NOT NULL,
              contract_address TEXT NOT NULL,
              contract_code_hash TEXT NOT NULL,
              finalized_block INTEGER NOT NULL,
              finalized_block_hash TEXT NOT NULL,
              snapshot_generation INTEGER NOT NULL,
              snapshot_json TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO ri_v2_meta(meta_key,meta_value) VALUES('schema_version','2');
            "#,
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO ri_v2_identities(
                 server_id,identity_json,identity_hash,object_version,status,valid_until,
                 registry_json,snapshot_generation
               ) VALUES(?,?,?,?,?,?,?,?)"#,
            params![
                identity.server_id,
                serde_json::to_string(&identity).unwrap(),
                object_hash(&identity).unwrap(),
                1,
                "ACTIVE",
                identity.valid_until,
                old_reference,
                7,
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO ri_v2_registry_snapshot(
                 snapshot_key,chain_id,contract_address,contract_code_hash,finalized_block,
                 finalized_block_hash,snapshot_generation,snapshot_json
               ) VALUES(?,?,?,?,?,?,?,?)"#,
            params![
                "registry-v2:operator/r1",
                31_337,
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222222222222222222222222222",
                100,
                "0x3333333333333333333333333333333333333333333333333333333333333333",
                7,
                old_reference,
            ],
        )
        .unwrap();
    drop(connection);

    let store = EvidenceStore::open(&path).unwrap();
    let (_, migrated) = store.get_identity("operator/r1").unwrap().unwrap();
    assert_eq!(migrated.chain_adapter, "evm");
    assert_eq!(migrated.chain_identity, "eip155:31337");
    assert!(matches!(
        migrated.adapter_metadata,
        RegistryAdapterMetadataV2::Evm {
            chain_id: 31_337,
            ..
        }
    ));
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT meta_value FROM ri_v2_meta WHERE meta_key='schema_version'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "3"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT adapter_type FROM ri_v2_registry_snapshot",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "evm"
    );
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
        sequence: 0,
        correlation_id: correlation_id.into(),
        parent_event_id: None,
        kind: TraceEventKind::ResolverResponse,
        observer_server_id: "operator/r1".into(),
        target_server_id: None,
        target_endpoint: None,
        target_correlation_id: None,
        attempt: None,
        query_digest: query_digest.into(),
        response_digest: Some(response_digest.into()),
        cache_object_digest: None,
        observed_at: 1_800_000_000,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: None,
        source_graph_digest: None,
        failure_reason: None,
    }
}

fn production_event(
    sequence: u64,
    kind: TraceEventKind,
    parent_event_id: Option<&str>,
) -> TraceEventV2 {
    TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: format!("event-{sequence}"),
        trace_id: "production-trace".into(),
        sequence,
        correlation_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        parent_event_id: parent_event_id.map(Into::into),
        kind,
        observer_server_id: "operator/r1".into(),
        target_server_id: None,
        target_endpoint: None,
        target_correlation_id: None,
        attempt: None,
        query_digest: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        response_digest: (kind == TraceEventKind::ClientResponse)
            .then(|| "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into()),
        cache_object_digest: None,
        observed_at: 1_800_000_000,
        dnssec_status: DnssecStatus::Secure,
        ttl_expires_at: None,
        source_graph_digest: None,
        failure_reason: None,
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
        chain_adapter: "evm".into(),
        chain_identity: "eip155:31337".into(),
        registry_locator: "evm:0x1111111111111111111111111111111111111111".into(),
        registry_schema_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
            .into(),
        adapter_metadata: RegistryAdapterMetadataV2::Evm {
            chain_id: 31_337,
            contract_address: "0x1111111111111111111111111111111111111111".into(),
            runtime_code_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .into(),
        },
        checkpoint_height: 100,
        checkpoint_hash: "0x3333333333333333333333333333333333333333333333333333333333333333"
            .into(),
        finality_type: RegistryFinalityTypeV2::EvmFinalized,
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
