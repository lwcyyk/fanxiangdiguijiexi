use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ri_core::{
    DnsEndpoint, DnsServerIdentityV2, QueryEvidenceGraphV2, RegistryAdapterMetadataV2,
    RegistryFinalityTypeV2, RegistryReferenceV2, TraceEventV2,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS ri_v2_meta (
  meta_key TEXT PRIMARY KEY,
  meta_value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ri_v2_identities (
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
CREATE TABLE IF NOT EXISTS ri_v2_endpoint_lookup (
  endpoint_key TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  FOREIGN KEY(server_id) REFERENCES ri_v2_identities(server_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ri_v2_trace_events (
  event_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  parent_event_id TEXT,
  event_json TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ri_v2_trace_events_trace_idx
  ON ri_v2_trace_events(trace_id, observed_at, event_id);
CREATE TABLE IF NOT EXISTS ri_v2_query_contexts (
  request_trace_id TEXT PRIMARY KEY,
  correlation_id TEXT NOT NULL,
  query_digest TEXT NOT NULL,
  min_event_rowid INTEGER NOT NULL,
  registered_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_event_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ri_v2_trace_event_claims (
  event_id TEXT PRIMARY KEY,
  request_trace_id TEXT NOT NULL,
  claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(event_id) REFERENCES ri_v2_trace_events(event_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ri_v2_evidence_graphs (
  trace_id TEXT PRIMARY KEY,
  query_digest TEXT NOT NULL,
  response_digest TEXT NOT NULL,
  graph_json TEXT NOT NULL,
  graph_digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  snapshot_generation INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ri_v2_evidence_graphs_query_idx
  ON ri_v2_evidence_graphs(query_digest, response_digest, expires_at);
CREATE TABLE IF NOT EXISTS ri_v2_registry_snapshot (
  snapshot_key TEXT PRIMARY KEY,
  chain_id INTEGER NOT NULL,
  contract_address TEXT NOT NULL,
  contract_code_hash TEXT NOT NULL,
  finalized_block INTEGER NOT NULL,
  finalized_block_hash TEXT NOT NULL,
  snapshot_generation INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  adapter_type TEXT NOT NULL,
  chain_identity TEXT NOT NULL,
  registry_locator TEXT NOT NULL,
  registry_schema_hash TEXT NOT NULL,
  finality_type TEXT NOT NULL,
  state_root TEXT NOT NULL,
  adapter_metadata_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("core validation error: {0}")]
    Core(#[from] ri_core::EvidenceValidationError),
}

#[derive(Clone, Debug)]
pub struct EvidenceStore {
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryCheckpoint {
    pub finalized_block: u64,
    pub finalized_block_hash: String,
}

pub struct TraceResponseMatch<'a> {
    pub request_trace_id: &'a str,
    pub server_id: &'a str,
    pub correlation_id: &'a str,
    pub query_digest: &'a str,
    pub response_digest: &'a str,
    pub endpoint: Option<&'a DnsEndpoint>,
    pub allow_authority_response: bool,
    pub not_before: i64,
    pub not_after: i64,
}

impl EvidenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
        };
        let mut connection = store.connect()?;
        connection.execute_batch(SCHEMA)?;
        if !table_has_column(&connection, "ri_v2_query_contexts", "registered_at")? {
            connection.execute(
                "ALTER TABLE ri_v2_query_contexts ADD COLUMN registered_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
            // Query contexts are short-lived and cannot be migrated without weakening
            // their request-time boundary.
            connection.execute("DELETE FROM ri_v2_query_contexts", [])?;
        }
        connection.execute(
            "INSERT OR IGNORE INTO ri_v2_meta(meta_key,meta_value) VALUES('schema_version','2')",
            [],
        )?;
        migrate_registry_schema(&mut connection)?;
        connection.execute(
            "INSERT OR IGNORE INTO ri_v2_meta(meta_key,meta_value) VALUES('cache_generation','0')",
            [],
        )?;
        connection.execute(
            r#"INSERT OR IGNORE INTO ri_v2_meta(meta_key,meta_value)
               VALUES('registry_last_success_epoch','0')"#,
            [],
        )?;
        Ok(store)
    }

    pub fn put_identity(
        &self,
        identity: &DnsServerIdentityV2,
        registry: &RegistryReferenceV2,
    ) -> Result<(), StoreError> {
        if registry.object_version != identity.object_version {
            return Err(StoreError::InvalidData(
                "identity and registry object_version differ".into(),
            ));
        }
        let identity_json = serde_json::to_string(identity)?;
        let registry_json = serde_json::to_string(registry)?;
        let identity_hash = ri_core::object_hash(identity)?;
        let object_version = sql_i64(identity.object_version, "object_version")?;
        let snapshot_generation = sql_i64(registry.snapshot_generation, "snapshot_generation")?;
        if identity_hash != registry.object_hash {
            return Err(StoreError::InvalidData(
                "identity hash does not match registry reference".into(),
            ));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let current = transaction
            .query_row(
                r#"SELECT identity_json,registry_json FROM ri_v2_identities
                   WHERE server_id=?"#,
                [&identity.server_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((current_identity_json, current_registry_json)) = current
            && current_identity_json == identity_json
        {
            let current_registry: RegistryReferenceV2 =
                serde_json::from_str(&current_registry_json)?;
            if same_registry_state(&current_registry, registry) {
                transaction.execute(
                    r#"UPDATE ri_v2_identities SET
                         registry_json=?,snapshot_generation=?,updated_at=CURRENT_TIMESTAMP
                       WHERE server_id=?"#,
                    params![registry_json, snapshot_generation, identity.server_id],
                )?;
                transaction.commit()?;
                return Ok(());
            }
        }
        transaction.execute(
            r#"INSERT INTO ri_v2_identities(
                 server_id,identity_json,identity_hash,object_version,status,valid_until,
                 registry_json,snapshot_generation
               ) VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(server_id) DO UPDATE SET
                 identity_json=excluded.identity_json,
                 identity_hash=excluded.identity_hash,
                 object_version=excluded.object_version,
                 status=excluded.status,
                 valid_until=excluded.valid_until,
                 registry_json=excluded.registry_json,
                 snapshot_generation=excluded.snapshot_generation,
                 updated_at=CURRENT_TIMESTAMP"#,
            params![
                identity.server_id,
                identity_json,
                identity_hash,
                object_version,
                identity.status,
                identity.valid_until,
                registry_json,
                snapshot_generation,
            ],
        )?;
        transaction.execute(
            "DELETE FROM ri_v2_endpoint_lookup WHERE server_id=?",
            [&identity.server_id],
        )?;
        for endpoint in &identity.endpoints {
            transaction.execute(
                "INSERT INTO ri_v2_endpoint_lookup(endpoint_key,server_id) VALUES(?,?)",
                params![endpoint.cache_key()?, identity.server_id],
            )?;
        }
        bump_generation(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn quarantine_identity(&self, server_id: &str, status: &str) -> Result<bool, StoreError> {
        let Some((identity, mut registry)) = self.get_identity(server_id)? else {
            return Ok(false);
        };
        if registry.resolver_status == status {
            return Ok(false);
        }
        registry.resolver_status = status.to_owned();
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"UPDATE ri_v2_identities SET
                 status=?,registry_json=?,updated_at=CURRENT_TIMESTAMP
               WHERE server_id=?"#,
            params![
                status,
                serde_json::to_string(&registry)?,
                identity.server_id
            ],
        )?;
        transaction.execute(
            "DELETE FROM ri_v2_endpoint_lookup WHERE server_id=?",
            [&identity.server_id],
        )?;
        bump_generation(&transaction)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn get_identity(
        &self,
        server_id: &str,
    ) -> Result<Option<(DnsServerIdentityV2, RegistryReferenceV2)>, StoreError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT identity_json,registry_json FROM ri_v2_identities WHERE server_id=?",
                [server_id],
                |row| {
                    let identity_json: String = row.get(0)?;
                    let registry_json: String = row.get(1)?;
                    Ok((identity_json, registry_json))
                },
            )
            .optional()?
            .map(|(identity, registry)| {
                Ok((
                    serde_json::from_str(&identity)?,
                    serde_json::from_str(&registry)?,
                ))
            })
            .transpose()
    }

    pub fn lookup_identity(
        &self,
        endpoint: &DnsEndpoint,
    ) -> Result<Option<(DnsServerIdentityV2, RegistryReferenceV2)>, StoreError> {
        let connection = self.connect()?;
        let server_id = connection
            .query_row(
                "SELECT server_id FROM ri_v2_endpoint_lookup WHERE endpoint_key=?",
                [endpoint.cache_key()?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        server_id
            .as_deref()
            .map(|value| self.get_identity(value))
            .transpose()
            .map(Option::flatten)
    }

    pub fn identity_ids(&self) -> Result<Vec<String>, StoreError> {
        let connection = self.connect()?;
        let mut statement =
            connection.prepare("SELECT server_id FROM ri_v2_identities ORDER BY server_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }

    pub fn put_trace_event(&self, event: &TraceEventV2) -> Result<(), StoreError> {
        self.put_trace_events(std::slice::from_ref(event))
    }

    pub fn put_trace_events(&self, events: &[TraceEventV2]) -> Result<(), StoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        for event in events {
            let event_json = serde_json::to_string(event)?;
            let inserted = transaction.execute(
                r#"INSERT INTO ri_v2_trace_events(
                 event_id,trace_id,parent_event_id,event_json,observed_at
               ) VALUES(?,?,?,?,?)
               ON CONFLICT(event_id) DO NOTHING"#,
                params![
                    event.event_id,
                    event.trace_id,
                    event.parent_event_id,
                    event_json,
                    event.observed_at,
                ],
            )?;
            if inserted == 0 {
                let existing = transaction.query_row(
                    "SELECT event_json FROM ri_v2_trace_events WHERE event_id=?",
                    [&event.event_id],
                    |row| row.get::<_, String>(0),
                )?;
                if existing != event_json {
                    return Err(StoreError::InvalidData(format!(
                        "trace event {} is immutable and conflicts with stored evidence",
                        event.event_id
                    )));
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn trace_events(&self, trace_id: &str) -> Result<Vec<TraceEventV2>, StoreError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT event_json FROM ri_v2_trace_events WHERE trace_id=? ORDER BY observed_at,event_id",
        )?;
        let rows = statement.query_map([trace_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let value = row?;
            serde_json::from_str(&value).map_err(StoreError::from)
        })
        .collect()
    }

    pub fn register_query_context(
        &self,
        request_trace_id: &str,
        correlation_id: &str,
        query_digest: &str,
        registered_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        if request_trace_id.is_empty()
            || correlation_id.is_empty()
            || query_digest.is_empty()
            || registered_at <= 0
            || expires_at <= 0
            || expires_at < registered_at
        {
            return Err(StoreError::InvalidData(
                "query context contains an invalid field".into(),
            ));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let min_event_rowid = transaction.query_row(
            "SELECT COALESCE(MAX(rowid),0)+1 FROM ri_v2_trace_events",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        transaction.execute(
            r#"INSERT INTO ri_v2_query_contexts(
                 request_trace_id,correlation_id,query_digest,min_event_rowid,registered_at,expires_at
               ) VALUES(?,?,?,?,?,?)"#,
            params![
                request_trace_id,
                correlation_id,
                query_digest,
                min_event_rowid,
                registered_at,
                expires_at
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn claim_registered_trace_anchor(
        &self,
        request_trace_id: &str,
        server_id: &str,
        correlation_id: &str,
        query_digest: &str,
        response_digest: &str,
        now: i64,
    ) -> Result<Option<TraceEventV2>, StoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let context = transaction
            .query_row(
                r#"SELECT correlation_id,query_digest,min_event_rowid,registered_at,expires_at,
                          consumed_event_id
                   FROM ri_v2_query_contexts WHERE request_trace_id=?"#,
                [request_trace_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::InvalidData("registered query context was not found".into())
            })?;
        if context.0 != correlation_id || context.1 != query_digest || context.4 < now {
            return Err(StoreError::InvalidData(
                "registered query context does not match or has expired".into(),
            ));
        }
        if context.5.is_some() {
            return Err(StoreError::InvalidData(
                "registered query context has already been consumed".into(),
            ));
        }
        let candidate = transaction
            .query_row(
                r#"SELECT event_id,event_json FROM ri_v2_trace_events
                   WHERE rowid>=?
                     AND observed_at>=?
                     AND observed_at<=?
                     AND json_extract(event_json,'$.observer_server_id')=?
                     AND json_extract(event_json,'$.correlation_id')=?
                     AND json_extract(event_json,'$.query_digest')=?
                     AND json_extract(event_json,'$.response_digest')=?
                     AND json_extract(event_json,'$.kind')='RESOLVER_RESPONSE'
                   ORDER BY rowid DESC LIMIT 1"#,
                params![
                    context.2,
                    context.3,
                    now.saturating_add(5),
                    server_id,
                    correlation_id,
                    query_digest,
                    response_digest
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((event_id, event_json)) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        claim_event(&transaction, &event_id, request_trace_id)?;
        let updated = transaction.execute(
            r#"UPDATE ri_v2_query_contexts SET consumed_event_id=?
               WHERE request_trace_id=? AND consumed_event_id IS NULL"#,
            params![event_id, request_trace_id],
        )?;
        if updated != 1 {
            return Err(StoreError::InvalidData(
                "query context was consumed concurrently".into(),
            ));
        }
        transaction.commit()?;
        Ok(Some(serde_json::from_str(&event_json)?))
    }

    pub fn claim_matching_response(
        &self,
        request: &TraceResponseMatch<'_>,
    ) -> Result<Option<TraceEventV2>, StoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            r#"SELECT event_id,event_json FROM ri_v2_trace_events
               WHERE observed_at>=?
                 AND observed_at<=?
                 AND json_extract(event_json,'$.observer_server_id')=?
                 AND json_extract(event_json,'$.correlation_id')=?
                 AND json_extract(event_json,'$.query_digest')=?
                 AND json_extract(event_json,'$.response_digest')=?
                 AND json_extract(event_json,'$.kind') IN
                     ('RESOLVER_RESPONSE','AUTHORITY_RESPONSE')
               ORDER BY observed_at DESC,rowid DESC"#,
        )?;
        let rows = statement.query_map(
            params![
                request.not_before,
                request.not_after,
                request.server_id,
                request.correlation_id,
                request.query_digest,
                request.response_digest
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut candidates = Vec::new();
        for row in rows {
            let (event_id, event_json) = row?;
            let event: TraceEventV2 = serde_json::from_str(&event_json)?;
            let kind_matches = event.kind == ri_core::TraceEventKind::ResolverResponse
                || (request.allow_authority_response
                    && event.kind == ri_core::TraceEventKind::AuthorityResponse);
            if kind_matches
                && request.endpoint.is_none_or(|expected| {
                    event
                        .target_endpoint
                        .as_ref()
                        .is_some_and(|candidate| expected.matches(candidate).unwrap_or(false))
                })
            {
                candidates.push((event_id, event));
            }
        }
        drop(statement);
        for (event_id, event) in candidates {
            let existing = transaction
                .query_row(
                    "SELECT request_trace_id FROM ri_v2_trace_event_claims WHERE event_id=?",
                    [&event_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match existing.as_deref() {
                Some(owner) if owner != request.request_trace_id => continue,
                Some(_) => {
                    transaction.commit()?;
                    return Ok(Some(event));
                }
                None => {
                    claim_event(&transaction, &event_id, request.request_trace_id)?;
                    transaction.commit()?;
                    return Ok(Some(event));
                }
            }
        }
        transaction.commit()?;
        Ok(None)
    }

    pub fn find_trace_events(
        &self,
        query_digest: &str,
        response_digest: &str,
        not_before: i64,
    ) -> Result<Vec<TraceEventV2>, StoreError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r#"SELECT event_json FROM ri_v2_trace_events
               WHERE observed_at>=?
                 AND json_extract(event_json,'$.query_digest')=?
                 AND json_extract(event_json,'$.response_digest')=?
               ORDER BY observed_at,event_id"#,
        )?;
        let rows = statement
            .query_map(params![not_before, query_digest, response_digest], |row| {
                row.get::<_, String>(0)
            })?;
        rows.map(|row| {
            let value = row?;
            serde_json::from_str(&value).map_err(StoreError::from)
        })
        .collect()
    }

    pub fn has_matching_response(
        &self,
        server_id: &str,
        correlation_id: &str,
        query_digest: &str,
        response_digest: &str,
        endpoint: &DnsEndpoint,
        not_before: i64,
    ) -> Result<bool, StoreError> {
        Ok(self
            .matching_response(
                server_id,
                correlation_id,
                query_digest,
                response_digest,
                endpoint,
                not_before,
            )?
            .is_some())
    }

    pub fn matching_response(
        &self,
        server_id: &str,
        correlation_id: &str,
        query_digest: &str,
        response_digest: &str,
        endpoint: &DnsEndpoint,
        not_before: i64,
    ) -> Result<Option<TraceEventV2>, StoreError> {
        Ok(self
            .find_trace_events(query_digest, response_digest, not_before)?
            .into_iter()
            .rev()
            .find(|event| {
                event.observer_server_id == server_id
                    && event.correlation_id == correlation_id
                    && event
                        .target_endpoint
                        .as_ref()
                        .is_some_and(|candidate| endpoint.matches(candidate).unwrap_or(false))
                    && matches!(
                        event.kind,
                        ri_core::TraceEventKind::ResolverResponse
                            | ri_core::TraceEventKind::AuthorityResponse
                    )
            }))
    }

    pub fn put_graph(&self, graph: &QueryEvidenceGraphV2) -> Result<String, StoreError> {
        let digest = ri_core::object_hash(graph)?;
        let generation = self.cache_generation()?;
        let generation_sql = sql_i64(generation, "cache_generation")?;
        let connection = self.connect()?;
        connection.execute(
            r#"INSERT INTO ri_v2_evidence_graphs(
                 trace_id,query_digest,response_digest,graph_json,graph_digest,expires_at,
                 snapshot_generation
               ) VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(trace_id) DO UPDATE SET
                 query_digest=excluded.query_digest,
                 response_digest=excluded.response_digest,
                 graph_json=excluded.graph_json,
                 graph_digest=excluded.graph_digest,
                 expires_at=excluded.expires_at,
                 snapshot_generation=excluded.snapshot_generation"#,
            params![
                graph.trace_id,
                graph.query_digest,
                graph.response_digest,
                serde_json::to_string(graph)?,
                digest,
                graph.expires_at,
                generation_sql,
            ],
        )?;
        Ok(digest)
    }

    pub fn get_graph(&self, trace_id: &str) -> Result<Option<QueryEvidenceGraphV2>, StoreError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT graph_json FROM ri_v2_evidence_graphs WHERE trace_id=?",
                [trace_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    pub fn find_cached_graph(
        &self,
        query_digest: &str,
        response_digest: &str,
        now: i64,
    ) -> Result<Option<QueryEvidenceGraphV2>, StoreError> {
        let generation = self.cache_generation()?;
        let generation_sql = sql_i64(generation, "cache_generation")?;
        let connection = self.connect()?;
        connection
            .query_row(
                r#"SELECT graph_json FROM ri_v2_evidence_graphs
                   WHERE query_digest=? AND response_digest=? AND expires_at>=?
                     AND snapshot_generation=?
                   ORDER BY expires_at DESC LIMIT 1"#,
                params![query_digest, response_digest, now, generation_sql],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    pub fn find_latest_source_graph(
        &self,
        query_digest: &str,
        response_digest: &str,
    ) -> Result<Option<(QueryEvidenceGraphV2, String)>, StoreError> {
        let generation = self.cache_generation()?;
        let generation_sql = sql_i64(generation, "cache_generation")?;
        let connection = self.connect()?;
        connection
            .query_row(
                r#"SELECT graph_json,graph_digest FROM ri_v2_evidence_graphs
                   WHERE query_digest=? AND response_digest=?
                     AND snapshot_generation=?
                   ORDER BY created_at DESC LIMIT 1"#,
                params![query_digest, response_digest, generation_sql],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(value, digest)| {
                Ok((
                    serde_json::from_str(&value).map_err(StoreError::from)?,
                    digest,
                ))
            })
            .transpose()
    }

    pub fn put_registry_snapshot(
        &self,
        key: &str,
        reference: &RegistryReferenceV2,
    ) -> Result<(), StoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let (chain_id, contract_address, runtime_code_hash) = legacy_evm_columns(reference)?;
        let finalized_block = sql_i64(reference.checkpoint_height, "checkpoint_height")?;
        let snapshot_generation = sql_i64(reference.snapshot_generation, "snapshot_generation")?;
        transaction.execute(
            r#"INSERT INTO ri_v2_registry_snapshot(
                 snapshot_key,chain_id,contract_address,contract_code_hash,finalized_block,
                 finalized_block_hash,snapshot_generation,snapshot_json,adapter_type,
                 chain_identity,registry_locator,registry_schema_hash,finality_type,state_root,
                 adapter_metadata_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(snapshot_key) DO UPDATE SET
                 chain_id=excluded.chain_id,
                 contract_address=excluded.contract_address,
                 contract_code_hash=excluded.contract_code_hash,
                 finalized_block=excluded.finalized_block,
                 finalized_block_hash=excluded.finalized_block_hash,
                 snapshot_generation=excluded.snapshot_generation,
                 snapshot_json=excluded.snapshot_json,
                 adapter_type=excluded.adapter_type,
                 chain_identity=excluded.chain_identity,
                 registry_locator=excluded.registry_locator,
                 registry_schema_hash=excluded.registry_schema_hash,
                 finality_type=excluded.finality_type,
                 state_root=excluded.state_root,
                 adapter_metadata_json=excluded.adapter_metadata_json,
                 updated_at=CURRENT_TIMESTAMP"#,
            params![
                key,
                chain_id,
                contract_address,
                runtime_code_hash,
                finalized_block,
                reference.checkpoint_hash,
                snapshot_generation,
                serde_json::to_string(reference)?,
                reference.chain_adapter,
                reference.chain_identity,
                reference.registry_locator,
                reference.registry_schema_hash,
                finality_type_name(reference.finality_type),
                reference.state_root,
                serde_json::to_string(&reference.adapter_metadata)?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn registry_checkpoint(&self) -> Result<Option<RegistryCheckpoint>, StoreError> {
        let connection = self.connect()?;
        registry_checkpoint_from(&connection)
    }

    pub fn apply_registry_snapshot(
        &self,
        records: &[(DnsServerIdentityV2, RegistryReferenceV2)],
        success_epoch: i64,
    ) -> Result<u64, StoreError> {
        if records.is_empty() || success_epoch <= 0 {
            return Err(StoreError::InvalidData(
                "Registry snapshot must contain records and a valid timestamp".into(),
            ));
        }
        let first = &records[0].1;
        let deployment = (
            first.chain_adapter.as_str(),
            first.chain_identity.as_str(),
            first.registry_locator.as_str(),
            first.registry_schema_hash.as_str(),
            &first.adapter_metadata,
            first.checkpoint_height,
            first.checkpoint_hash.as_str(),
            first.finality_type,
            first.snapshot_generation,
            first.state_root.as_str(),
        );
        let mut configured_ids = HashSet::new();
        let mut configured_endpoints = HashSet::new();
        for (identity, reference) in records {
            if reference.object_version != identity.object_version
                || reference.object_hash != ri_core::object_hash(identity)?
                || (
                    reference.chain_adapter.as_str(),
                    reference.chain_identity.as_str(),
                    reference.registry_locator.as_str(),
                    reference.registry_schema_hash.as_str(),
                    &reference.adapter_metadata,
                    reference.checkpoint_height,
                    reference.checkpoint_hash.as_str(),
                    reference.finality_type,
                    reference.snapshot_generation,
                    reference.state_root.as_str(),
                ) != deployment
            {
                return Err(StoreError::InvalidData(
                    "Registry snapshot records are inconsistent".into(),
                ));
            }
            if !configured_ids.insert(identity.server_id.clone()) {
                return Err(StoreError::InvalidData(format!(
                    "duplicate Registry identity {}",
                    identity.server_id
                )));
            }
            for endpoint in &identity.endpoints {
                let endpoint_key = endpoint.cache_key()?;
                if !configured_endpoints.insert(endpoint_key.clone()) {
                    return Err(StoreError::InvalidData(format!(
                        "duplicate Registry endpoint {endpoint_key}"
                    )));
                }
            }
        }

        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_reference = transaction
            .query_row(
                "SELECT registry_json FROM ri_v2_identities ORDER BY server_id LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| serde_json::from_str::<RegistryReferenceV2>(&value))
            .transpose()?;
        if let Some(existing) = existing_reference.as_ref()
            && (existing.chain_adapter != first.chain_adapter
                || existing.adapter_metadata != first.adapter_metadata
                || (!existing.chain_identity.is_empty()
                    && existing.chain_identity != first.chain_identity)
                || (!existing.registry_locator.is_empty()
                    && existing.registry_locator != first.registry_locator)
                || (!existing.registry_schema_hash.is_empty()
                    && existing.registry_schema_hash != first.registry_schema_hash))
        {
            return Err(StoreError::InvalidData(
                "Registry target changed; use a new database".into(),
            ));
        }
        if let Some(existing) = existing_reference.as_ref() {
            if first.snapshot_generation < existing.snapshot_generation {
                return Err(StoreError::InvalidData(format!(
                    "Registry source generation rollback: stored {}, received {}",
                    existing.snapshot_generation, first.snapshot_generation
                )));
            }
            if first.snapshot_generation == existing.snapshot_generation
                && first.state_root != existing.state_root
            {
                return Err(StoreError::InvalidData(
                    "Registry state root changed at the stored source generation".into(),
                ));
            }
        }
        for (key, expected) in [
            ("registry_chain_adapter", first.chain_adapter.as_str()),
            ("registry_chain_identity", first.chain_identity.as_str()),
            ("registry_locator", first.registry_locator.as_str()),
            ("registry_schema_hash", first.registry_schema_hash.as_str()),
        ] {
            let stored = transaction
                .query_row(
                    "SELECT meta_value FROM ri_v2_meta WHERE meta_key=?",
                    [key],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if stored.as_deref().is_some_and(|value| value != expected) {
                return Err(StoreError::InvalidData(format!(
                    "Registry target changed for {key}; use a new database"
                )));
            }
        }
        if let Some(checkpoint) = registry_checkpoint_from(&transaction)? {
            if first.checkpoint_height < checkpoint.finalized_block {
                return Err(StoreError::InvalidData(format!(
                    "finalized block rollback: stored {}, received {}",
                    checkpoint.finalized_block, first.checkpoint_height
                )));
            }
            if first.checkpoint_height == checkpoint.finalized_block
                && first.checkpoint_hash != checkpoint.finalized_block_hash
            {
                return Err(StoreError::InvalidData(
                    "finalized block hash changed at the stored height".into(),
                ));
            }
        }

        let mut statement =
            transaction.prepare("SELECT server_id FROM ri_v2_identities ORDER BY server_id")?;
        let existing_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut semantic_change = false;
        for server_id in existing_ids {
            if configured_ids.contains(&server_id) {
                continue;
            }
            let current_registry = transaction
                .query_row(
                    "SELECT registry_json FROM ri_v2_identities WHERE server_id=?",
                    [&server_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(current_registry) = current_registry {
                let mut reference: RegistryReferenceV2 = serde_json::from_str(&current_registry)?;
                if reference.resolver_status != "REMOVED" {
                    semantic_change = true;
                    reference.resolver_status = "REMOVED".into();
                    transaction.execute(
                        r#"UPDATE ri_v2_identities SET
                             status='REMOVED',registry_json=?,updated_at=CURRENT_TIMESTAMP
                           WHERE server_id=?"#,
                        params![serde_json::to_string(&reference)?, server_id],
                    )?;
                }
            }
            transaction.execute(
                "DELETE FROM ri_v2_endpoint_lookup WHERE server_id=?",
                [&server_id],
            )?;
            transaction.execute(
                "DELETE FROM ri_v2_registry_snapshot WHERE snapshot_key=?",
                [format!("registry-v2:{server_id}")],
            )?;
        }

        for (identity, reference) in records {
            let (legacy_chain_id, legacy_contract_address, legacy_runtime_code_hash) =
                legacy_evm_columns(reference)?;
            let identity_json = serde_json::to_string(identity)?;
            let registry_json = serde_json::to_string(reference)?;
            let current = transaction
                .query_row(
                    r#"SELECT identity_json,registry_json FROM ri_v2_identities
                       WHERE server_id=?"#,
                    [&identity.server_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let same_semantics = current
                .as_ref()
                .and_then(|(current_identity, current_registry)| {
                    serde_json::from_str::<RegistryReferenceV2>(current_registry)
                        .ok()
                        .map(|current_registry| {
                            current_identity == &identity_json
                                && same_registry_state(&current_registry, reference)
                        })
                })
                .unwrap_or(false);
            semantic_change |= !same_semantics;

            transaction.execute(
                r#"INSERT INTO ri_v2_identities(
                     server_id,identity_json,identity_hash,object_version,status,valid_until,
                     registry_json,snapshot_generation
                   ) VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(server_id) DO UPDATE SET
                     identity_json=excluded.identity_json,
                     identity_hash=excluded.identity_hash,
                     object_version=excluded.object_version,
                     status=excluded.status,
                     valid_until=excluded.valid_until,
                     registry_json=excluded.registry_json,
                     snapshot_generation=excluded.snapshot_generation,
                     updated_at=CURRENT_TIMESTAMP"#,
                params![
                    identity.server_id,
                    identity_json,
                    reference.object_hash,
                    sql_i64(identity.object_version, "object_version")?,
                    identity.status,
                    identity.valid_until,
                    registry_json,
                    sql_i64(reference.snapshot_generation, "snapshot_generation")?,
                ],
            )?;
            transaction.execute(
                "DELETE FROM ri_v2_endpoint_lookup WHERE server_id=?",
                [&identity.server_id],
            )?;
            for endpoint in &identity.endpoints {
                transaction.execute(
                    "INSERT INTO ri_v2_endpoint_lookup(endpoint_key,server_id) VALUES(?,?)",
                    params![endpoint.cache_key()?, identity.server_id],
                )?;
            }
            transaction.execute(
                r#"INSERT INTO ri_v2_registry_snapshot(
                     snapshot_key,chain_id,contract_address,contract_code_hash,finalized_block,
                     finalized_block_hash,snapshot_generation,snapshot_json,adapter_type,
                     chain_identity,registry_locator,registry_schema_hash,finality_type,state_root,
                     adapter_metadata_json
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(snapshot_key) DO UPDATE SET
                     chain_id=excluded.chain_id,
                     contract_address=excluded.contract_address,
                     contract_code_hash=excluded.contract_code_hash,
                     finalized_block=excluded.finalized_block,
                     finalized_block_hash=excluded.finalized_block_hash,
                     snapshot_generation=excluded.snapshot_generation,
                     snapshot_json=excluded.snapshot_json,
                     adapter_type=excluded.adapter_type,
                     chain_identity=excluded.chain_identity,
                     registry_locator=excluded.registry_locator,
                     registry_schema_hash=excluded.registry_schema_hash,
                     finality_type=excluded.finality_type,
                     state_root=excluded.state_root,
                     adapter_metadata_json=excluded.adapter_metadata_json,
                     updated_at=CURRENT_TIMESTAMP"#,
                params![
                    format!("registry-v2:{}", identity.server_id),
                    legacy_chain_id,
                    legacy_contract_address,
                    legacy_runtime_code_hash,
                    sql_i64(reference.checkpoint_height, "checkpoint_height")?,
                    reference.checkpoint_hash,
                    sql_i64(reference.snapshot_generation, "snapshot_generation")?,
                    serde_json::to_string(reference)?,
                    reference.chain_adapter,
                    reference.chain_identity,
                    reference.registry_locator,
                    reference.registry_schema_hash,
                    finality_type_name(reference.finality_type),
                    reference.state_root,
                    serde_json::to_string(&reference.adapter_metadata)?,
                ],
            )?;
        }

        let generation = if semantic_change {
            bump_generation(&transaction)?
        } else {
            cache_generation_from(&transaction)?
        };
        set_meta(
            &transaction,
            "registry_finalized_block",
            &first.checkpoint_height.to_string(),
        )?;
        set_meta(
            &transaction,
            "registry_finalized_block_hash",
            &first.checkpoint_hash,
        )?;
        set_meta(
            &transaction,
            "registry_last_success_epoch",
            &success_epoch.to_string(),
        )?;
        set_meta(&transaction, "registry_chain_adapter", &first.chain_adapter)?;
        set_meta(
            &transaction,
            "registry_chain_identity",
            &first.chain_identity,
        )?;
        set_meta(&transaction, "registry_locator", &first.registry_locator)?;
        set_meta(
            &transaction,
            "registry_schema_hash",
            &first.registry_schema_hash,
        )?;
        transaction.commit()?;
        Ok(generation)
    }

    pub fn cache_generation(&self) -> Result<u64, StoreError> {
        let connection = self.connect()?;
        let value = connection.query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='cache_generation'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        value
            .parse()
            .map_err(|_| StoreError::InvalidData("cache generation is not an integer".into()))
    }

    pub fn invalidate_all(&self) -> Result<u64, StoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let generation = bump_generation(&transaction)?;
        transaction.execute("DELETE FROM ri_v2_evidence_graphs", [])?;
        transaction.commit()?;
        Ok(generation)
    }

    pub fn mark_registry_sync_success(&self, epoch: i64) -> Result<(), StoreError> {
        if epoch <= 0 {
            return Err(StoreError::InvalidData(
                "registry sync epoch must be positive".into(),
            ));
        }
        let connection = self.connect()?;
        connection.execute(
            r#"INSERT INTO ri_v2_meta(meta_key,meta_value)
               VALUES('registry_last_success_epoch',?)
               ON CONFLICT(meta_key) DO UPDATE SET
                 meta_value=excluded.meta_value,
                 updated_at=CURRENT_TIMESTAMP"#,
            [epoch.to_string()],
        )?;
        Ok(())
    }

    pub fn registry_last_success_epoch(&self) -> Result<i64, StoreError> {
        let connection = self.connect()?;
        let value = connection.query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_last_success_epoch'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        value
            .parse()
            .map_err(|_| StoreError::InvalidData("registry sync epoch is invalid".into()))
    }

    pub fn purge_expired(&self, now: i64) -> Result<usize, StoreError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "DELETE FROM ri_v2_evidence_graphs WHERE expires_at<?",
            [now],
        )?)
    }

    pub fn purge_trace_events(&self, observed_before: i64) -> Result<usize, StoreError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "DELETE FROM ri_v2_trace_events WHERE observed_at<?",
            [observed_before],
        )?)
    }

    pub fn purge_query_contexts(&self, now: i64) -> Result<usize, StoreError> {
        let connection = self.connect()?;
        Ok(connection.execute("DELETE FROM ri_v2_query_contexts WHERE expires_at<?", [now])?)
    }

    fn connect(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(connection)
    }
}

fn claim_event(
    transaction: &Transaction<'_>,
    event_id: &str,
    request_trace_id: &str,
) -> Result<(), StoreError> {
    let inserted = transaction.execute(
        r#"INSERT INTO ri_v2_trace_event_claims(event_id,request_trace_id)
           VALUES(?,?) ON CONFLICT(event_id) DO NOTHING"#,
        params![event_id, request_trace_id],
    )?;
    if inserted == 1 {
        return Ok(());
    }
    let owner = transaction.query_row(
        "SELECT request_trace_id FROM ri_v2_trace_event_claims WHERE event_id=?",
        [event_id],
        |row| row.get::<_, String>(0),
    )?;
    if owner == request_trace_id {
        Ok(())
    } else {
        Err(StoreError::InvalidData(
            "Trace event is already bound to a different request".into(),
        ))
    }
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, StoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn migrate_registry_schema(connection: &mut Connection) -> Result<(), StoreError> {
    for (column, definition) in [
        ("adapter_type", "TEXT NOT NULL DEFAULT ''"),
        ("chain_identity", "TEXT NOT NULL DEFAULT ''"),
        ("registry_locator", "TEXT NOT NULL DEFAULT ''"),
        ("registry_schema_hash", "TEXT NOT NULL DEFAULT ''"),
        ("finality_type", "TEXT NOT NULL DEFAULT ''"),
        ("state_root", "TEXT NOT NULL DEFAULT ''"),
        ("adapter_metadata_json", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !table_has_column(connection, "ri_v2_registry_snapshot", column)? {
            connection.execute(
                &format!("ALTER TABLE ri_v2_registry_snapshot ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }

    let version = connection
        .query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )?
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidData("database schema version is invalid".into()))?;
    if version > 3 {
        return Err(StoreError::InvalidData(format!(
            "database schema version {version} is newer than supported version 3"
        )));
    }
    if version == 3 {
        return Ok(());
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let snapshots = {
        let mut statement = transaction
            .prepare("SELECT snapshot_key,snapshot_json FROM ri_v2_registry_snapshot")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (snapshot_key, snapshot_json) in snapshots {
        let reference: RegistryReferenceV2 = serde_json::from_str(&snapshot_json)?;
        transaction.execute(
            r#"UPDATE ri_v2_registry_snapshot SET
                 snapshot_json=?,adapter_type=?,chain_identity=?,registry_locator=?,
                 registry_schema_hash=?,finality_type=?,state_root=?,adapter_metadata_json=?
               WHERE snapshot_key=?"#,
            params![
                serde_json::to_string(&reference)?,
                reference.chain_adapter,
                reference.chain_identity,
                reference.registry_locator,
                reference.registry_schema_hash,
                finality_type_name(reference.finality_type),
                reference.state_root,
                serde_json::to_string(&reference.adapter_metadata)?,
                snapshot_key,
            ],
        )?;
    }

    let identities = {
        let mut statement =
            transaction.prepare("SELECT server_id,registry_json FROM ri_v2_identities")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (server_id, registry_json) in identities {
        let reference: RegistryReferenceV2 = serde_json::from_str(&registry_json)?;
        transaction.execute(
            "UPDATE ri_v2_identities SET registry_json=? WHERE server_id=?",
            params![serde_json::to_string(&reference)?, server_id],
        )?;
    }
    set_meta(&transaction, "schema_version", "3")?;
    transaction.commit()?;
    Ok(())
}

fn finality_type_name(value: RegistryFinalityTypeV2) -> &'static str {
    match value {
        RegistryFinalityTypeV2::EvmFinalized => "evm-finalized",
        RegistryFinalityTypeV2::EvmConfirmations => "evm-confirmations",
        RegistryFinalityTypeV2::EvmFinalizedOrConfirmations => "evm-finalized-or-confirmations",
        RegistryFinalityTypeV2::NornDualNodeConfirmations => "norn-dual-node-confirmations",
        RegistryFinalityTypeV2::ExternalSignedCheckpoint => "external-signed-checkpoint",
    }
}

fn bump_generation(transaction: &Transaction<'_>) -> Result<u64, StoreError> {
    let current = transaction.query_row(
        "SELECT meta_value FROM ri_v2_meta WHERE meta_key='cache_generation'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let next = current
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidData("cache generation is not an integer".into()))?
        .saturating_add(1);
    bump_generation_to(transaction, next)?;
    Ok(next)
}

fn cache_generation_from(connection: &Connection) -> Result<u64, StoreError> {
    let value = connection.query_row(
        "SELECT meta_value FROM ri_v2_meta WHERE meta_key='cache_generation'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    value
        .parse()
        .map_err(|_| StoreError::InvalidData("cache generation is not an integer".into()))
}

fn registry_checkpoint_from(
    connection: &Connection,
) -> Result<Option<RegistryCheckpoint>, StoreError> {
    let block = connection
        .query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_finalized_block'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let hash = connection
        .query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_finalized_block_hash'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match (block, hash) {
        (None, None) => Ok(None),
        (Some(block), Some(finalized_block_hash)) => Ok(Some(RegistryCheckpoint {
            finalized_block: block.parse().map_err(|_| {
                StoreError::InvalidData("Registry finalized block is invalid".into())
            })?,
            finalized_block_hash,
        })),
        _ => Err(StoreError::InvalidData(
            "Registry checkpoint is incomplete".into(),
        )),
    }
}

fn set_meta(transaction: &Transaction<'_>, key: &str, value: &str) -> Result<(), StoreError> {
    transaction.execute(
        r#"INSERT INTO ri_v2_meta(meta_key,meta_value) VALUES(?,?)
           ON CONFLICT(meta_key) DO UPDATE SET
             meta_value=excluded.meta_value,
             updated_at=CURRENT_TIMESTAMP"#,
        params![key, value],
    )?;
    Ok(())
}

fn bump_generation_to(transaction: &Transaction<'_>, generation: u64) -> Result<(), StoreError> {
    let current = transaction
        .query_row(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='cache_generation'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map_or(Ok(0), |value| {
            value
                .parse::<u64>()
                .map_err(|_| StoreError::InvalidData("cache generation is not an integer".into()))
        })?;
    if generation <= current {
        return Ok(());
    }
    transaction.execute(
        r#"INSERT INTO ri_v2_meta(meta_key,meta_value) VALUES('cache_generation',?)
           ON CONFLICT(meta_key) DO UPDATE SET
             meta_value=excluded.meta_value,
             updated_at=CURRENT_TIMESTAMP"#,
        [generation.to_string()],
    )?;
    transaction.execute("DELETE FROM ri_v2_evidence_graphs", [])?;
    Ok(())
}

fn sql_i64(value: u64, field: &str) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::InvalidData(format!("{field} exceeds SQLite INTEGER range")))
}

fn legacy_evm_columns(reference: &RegistryReferenceV2) -> Result<(i64, &str, &str), StoreError> {
    match &reference.adapter_metadata {
        RegistryAdapterMetadataV2::Evm {
            chain_id,
            contract_address,
            runtime_code_hash,
        } => Ok((
            sql_i64(*chain_id, "evm_chain_id")?,
            contract_address,
            runtime_code_hash,
        )),
        RegistryAdapterMetadataV2::Norn { .. } | RegistryAdapterMetadataV2::External { .. } => {
            Ok((0, "", ""))
        }
    }
}

pub fn same_registry_state(left: &RegistryReferenceV2, right: &RegistryReferenceV2) -> bool {
    left.chain_adapter == right.chain_adapter
        && left.chain_identity == right.chain_identity
        && left.registry_locator == right.registry_locator
        && left.registry_schema_hash == right.registry_schema_hash
        && left.adapter_metadata == right.adapter_metadata
        && left.state_root == right.state_root
        && left.object_hash == right.object_hash
        && left.object_version == right.object_version
        && left.resolver_status == right.resolver_status
        && left.root_status == right.root_status
        && left.endpoint_binding_status == right.endpoint_binding_status
}
