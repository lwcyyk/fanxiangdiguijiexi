use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{Certificate, Client, Identity, Url};
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, resolver_id_key, sha256_hex, verify_ed25519,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AdapterResult, ChainSnapshot, ChainTarget, FinalizedCheckpoint, RegistryChainAdapter,
    RegistryRecord, ensure_crypto_provider, is_zero_hex, normalize_hash,
};

pub const EXTERNAL_REGISTRY_SNAPSHOT_V1: &str = "resolver-identity-external-registry-snapshot-v1";

#[derive(Clone, Debug)]
pub struct ExternalAdapterConfig {
    /// Short chain driver name, for example `fabric`, `cosmos`, or `substrate`.
    pub driver: String,
    /// Independent base URLs implementing the Resolver Identity adapter protocol.
    pub endpoints: Vec<String>,
    pub target: ChainTarget,
    pub signer_issuer: String,
    pub signer_key_id: String,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub tls: Option<ExternalClientTlsMaterial>,
    pub production: bool,
}

#[derive(Clone, Debug)]
pub struct ExternalClientTlsMaterial {
    pub ca_certificate_pem: Vec<u8>,
    pub client_certificate_pem: Vec<u8>,
    pub client_private_key_pem: Vec<u8>,
}

pub struct ExternalRegistryAdapter {
    target: ChainTarget,
    signer_issuer: String,
    signer_key_id: String,
    clients: Vec<ExternalProtocolClient>,
}

impl ExternalRegistryAdapter {
    pub fn new(mut config: ExternalAdapterConfig) -> AdapterResult<Self> {
        ensure_crypto_provider();
        if config.driver.is_empty()
            || config.driver.len() > 23
            || !config
                .driver
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(
                "external adapter driver must be a lowercase slug of at most 23 bytes".into(),
            );
        }
        let expected_adapter = format!("external-{}", config.driver);
        if config.target.adapter != expected_adapter
            || config.target.chain_identity.is_empty()
            || config.target.registry_locator.is_empty()
            || config.target.evm.is_some()
            || config.signer_issuer.is_empty()
            || config.signer_key_id.is_empty()
            || config.request_timeout.is_zero()
            || config.max_response_bytes < 1_024
        {
            return Err("external adapter target pins, signer pins, or limits are invalid".into());
        }
        config.target.registry_schema_hash =
            normalize_hash(&config.target.registry_schema_hash, 32)?;
        if is_zero_hex(&config.target.registry_schema_hash) {
            return Err("external adapter Registry schema hash cannot be zero".into());
        }

        let unique_endpoints = config.endpoints.iter().collect::<HashSet<_>>();
        if config.endpoints.is_empty() || unique_endpoints.len() != config.endpoints.len() {
            return Err("external adapter endpoints must be non-empty and unique".into());
        }
        if config.production
            && (config.endpoints.len() < 2
                || config
                    .endpoints
                    .iter()
                    .any(|endpoint| !endpoint.starts_with("https://")))
        {
            return Err(
                "production external adapters require two independent HTTPS endpoints".into(),
            );
        }
        let clients = config
            .endpoints
            .into_iter()
            .map(|endpoint| {
                ExternalProtocolClient::new(
                    endpoint,
                    config.request_timeout,
                    config.max_response_bytes,
                    config.tls.as_ref(),
                    config.production,
                )
            })
            .collect::<AdapterResult<Vec<_>>>()?;
        Ok(Self {
            target: config.target,
            signer_issuer: config.signer_issuer,
            signer_key_id: config.signer_key_id,
            clients,
        })
    }

    async fn agreed_snapshot(&self) -> AdapterResult<ExternalRegistrySnapshotV1> {
        let mut accepted: Option<ExternalRegistrySnapshotV1> = None;
        for client in &self.clients {
            let snapshot = client.snapshot().await?;
            match &accepted {
                Some(previous) if previous != &snapshot => {
                    return Err("external adapter endpoints returned different snapshots".into());
                }
                None => accepted = Some(snapshot),
                _ => {}
            }
        }
        accepted.ok_or_else(|| "external adapter has no protocol clients".into())
    }

    async fn agreed_block(&self, number: u64) -> AdapterResult<FinalizedCheckpoint> {
        let mut accepted: Option<FinalizedCheckpoint> = None;
        for client in &self.clients {
            let checkpoint = client.block(number).await?;
            if checkpoint.number != number {
                return Err(format!(
                    "external adapter returned block {} for requested block {number}",
                    checkpoint.number
                )
                .into());
            }
            let checkpoint = FinalizedCheckpoint {
                number,
                hash: normalize_hash(&checkpoint.hash, 32)?,
            };
            match &accepted {
                Some(previous) if previous != &checkpoint => {
                    return Err(
                        format!("external adapter endpoints disagree at block {number}").into(),
                    );
                }
                None => accepted = Some(checkpoint),
                _ => {}
            }
        }
        accepted.ok_or_else(|| "external adapter has no protocol clients".into())
    }

    fn validate_snapshot(
        &self,
        snapshot: &ExternalRegistrySnapshotV1,
        issuer_keys: &IssuerKeyRegistry,
        now: i64,
    ) -> AdapterResult<BTreeMap<String, RegistryRecord>> {
        if snapshot.schema_version != EXTERNAL_REGISTRY_SNAPSHOT_V1
            || snapshot.target != self.target
            || snapshot.generation == 0
            || snapshot.checkpoint.number == 0
            || snapshot.root_status != "ACTIVE"
            || snapshot.published_at <= 0
            || snapshot.published_at > now
            || snapshot.valid_until < now
            || snapshot.valid_until <= snapshot.published_at
            || snapshot.issuer != self.signer_issuer
            || snapshot.key_id != self.signer_key_id
            || snapshot.entries.is_empty()
        {
            return Err("external Registry snapshot pins or validity window are invalid".into());
        }
        normalize_hash(&snapshot.checkpoint.hash, 32)?;
        let state_root = normalize_hash(&snapshot.state_root, 32)?;
        let public_key = issuer_keys
            .get(&snapshot.issuer, &snapshot.key_id)
            .ok_or("external snapshot signer is not trusted")?;
        verify_ed25519(snapshot, public_key)?;
        let calculated_root = external_state_root(&snapshot.entries)?;
        if calculated_root != state_root {
            return Err(format!(
                "external snapshot state root mismatch: expected {state_root}, got {calculated_root}"
            )
            .into());
        }
        snapshot_records(snapshot, &state_root)
    }
}

#[async_trait]
impl RegistryChainAdapter for ExternalRegistryAdapter {
    fn target(&self) -> &ChainTarget {
        &self.target
    }

    async fn read_snapshot(
        &self,
        _identities: &[DnsServerIdentityV2],
        issuer_keys: &IssuerKeyRegistry,
        now: i64,
    ) -> AdapterResult<ChainSnapshot> {
        let snapshot = self.agreed_snapshot().await?;
        let records = self.validate_snapshot(&snapshot, issuer_keys, now)?;
        let canonical = self.agreed_block(snapshot.checkpoint.number).await?;
        if canonical != snapshot.checkpoint {
            return Err("external snapshot checkpoint is not canonical".into());
        }
        Ok(ChainSnapshot {
            checkpoint: canonical,
            generation: snapshot.generation,
            records,
        })
    }

    async fn block_hash(&self, number: u64) -> AdapterResult<String> {
        Ok(self.agreed_block(number).await?.hash)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRegistrySnapshotV1 {
    pub schema_version: String,
    pub target: ChainTarget,
    pub checkpoint: FinalizedCheckpoint,
    pub generation: u64,
    pub state_root: String,
    pub root_status: String,
    pub published_at: i64,
    pub valid_until: i64,
    pub issuer: String,
    pub key_id: String,
    pub entries: Vec<ExternalRegistrySnapshotEntryV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRegistrySnapshotEntryV1 {
    pub server_id: String,
    pub resolver_id_key: String,
    pub object_hash: String,
    pub object_version: u64,
    pub valid_until: i64,
    pub status: String,
    pub endpoint_keys: Vec<String>,
}

fn snapshot_records(
    snapshot: &ExternalRegistrySnapshotV1,
    state_root: &str,
) -> AdapterResult<BTreeMap<String, RegistryRecord>> {
    let mut records = BTreeMap::new();
    let mut resolver_keys = HashSet::new();
    let mut all_endpoints = HashSet::new();
    for entry in &snapshot.entries {
        let resolver_key = normalize_hash(&entry.resolver_id_key, 32)?;
        if entry.server_id.is_empty()
            || entry.object_version == 0
            || entry.valid_until <= 0
            || entry.status.is_empty()
            || entry.endpoint_keys.is_empty()
            || resolver_key != resolver_id_key(&entry.server_id)
            || !resolver_keys.insert(resolver_key.clone())
        {
            return Err(format!("invalid external snapshot entry {}", entry.server_id).into());
        }
        let mut endpoint_owners = BTreeMap::new();
        for endpoint in &entry.endpoint_keys {
            let endpoint = normalize_hash(endpoint, 32)?;
            if !all_endpoints.insert(endpoint.clone()) {
                return Err(format!("duplicate external Registry endpoint {endpoint}").into());
            }
            endpoint_owners.insert(endpoint, resolver_key.clone());
        }
        if records
            .insert(
                entry.server_id.clone(),
                RegistryRecord {
                    resolver_id_key: resolver_key,
                    object_hash: normalize_hash(&entry.object_hash, 32)?,
                    state_root: state_root.into(),
                    object_version: entry.object_version,
                    valid_until: entry.valid_until,
                    resolver_status: entry.status.clone(),
                    root_status: snapshot.root_status.clone(),
                    endpoint_owners,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate external server_id {}", entry.server_id).into());
        }
    }
    Ok(records)
}

fn external_state_root(entries: &[ExternalRegistrySnapshotEntryV1]) -> AdapterResult<String> {
    let mut previous_server_id: Option<&str> = None;
    let mut level = Vec::with_capacity(entries.len());
    for entry in entries {
        if previous_server_id.is_some_and(|previous| previous >= entry.server_id.as_str()) {
            return Err("external snapshot entries must be sorted by unique server_id".into());
        }
        previous_server_id = Some(&entry.server_id);
        let resolver_key = normalize_hash(&entry.resolver_id_key, 32)?;
        let object_hash = normalize_hash(&entry.object_hash, 32)?;
        level.push(sha256_hex(format!(
            "resolver-leaf-v1|{resolver_key}|{object_hash}|{}|{}",
            entry.object_version,
            entry.status.to_ascii_uppercase()
        )));
    }
    if level.is_empty() {
        return Ok(sha256_hex("empty-root-v1"));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut payload = b"node-v1".to_vec();
            payload.extend_from_slice(&hex::decode(pair[0].trim_start_matches("0x"))?);
            payload.extend_from_slice(&hex::decode(right.trim_start_matches("0x"))?);
            next.push(sha256_hex(payload));
        }
        level = next;
    }
    Ok(level.remove(0))
}

struct ExternalProtocolClient {
    base_url: Url,
    client: Client,
    max_response_bytes: usize,
}

impl ExternalProtocolClient {
    fn new(
        base_url: String,
        timeout: Duration,
        max_response_bytes: usize,
        tls: Option<&ExternalClientTlsMaterial>,
        production: bool,
    ) -> AdapterResult<Self> {
        let base_url = Url::parse(&base_url)?;
        if production && base_url.scheme() != "https" {
            return Err("production external adapter endpoint must use HTTPS".into());
        }
        if !matches!(base_url.scheme(), "http" | "https") || base_url.cannot_be_a_base() {
            return Err("external adapter endpoint must be an HTTP(S) base URL".into());
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.host_str().is_none()
        {
            return Err(
                "external adapter endpoint must not contain credentials, query, or fragment".into(),
            );
        }
        let mut builder = Client::builder()
            .https_only(production)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(material) = tls {
            if material.ca_certificate_pem.is_empty()
                || material.client_certificate_pem.is_empty()
                || material.client_private_key_pem.is_empty()
            {
                return Err("external adapter mTLS material is incomplete".into());
            }
            let mut identity_pem = material.client_certificate_pem.clone();
            if !identity_pem.ends_with(b"\n") {
                identity_pem.push(b'\n');
            }
            identity_pem.extend_from_slice(&material.client_private_key_pem);
            builder = builder
                .add_root_certificate(Certificate::from_pem(&material.ca_certificate_pem)?)
                .identity(Identity::from_pem(&identity_pem)?);
        }
        let client = builder.build()?;
        Ok(Self {
            base_url,
            client,
            max_response_bytes,
        })
    }

    async fn snapshot(&self) -> AdapterResult<ExternalRegistrySnapshotV1> {
        self.get_json("v1/registry/snapshot").await
    }

    async fn block(&self, number: u64) -> AdapterResult<FinalizedCheckpoint> {
        self.get_json(&format!("v1/blocks/{number}")).await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> AdapterResult<T> {
        let url = self.base_url.join(path)?;
        let response = self.client.get(url).send().await?.error_for_status()?;
        let declared = response.content_length().unwrap_or(0);
        if declared > self.max_response_bytes as u64 {
            return Err("external adapter response exceeds configured limit".into());
        }
        let mut body = Vec::with_capacity(
            usize::try_from(declared)
                .unwrap_or(self.max_response_bytes)
                .min(self.max_response_bytes),
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err("external adapter response exceeds configured limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::{Path, State};
    use axum::response::Redirect;
    use axum::routing::get;
    use axum::{Json, Router};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use ri_core::{IssuerKeyRegistry, resolver_id_key};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{
        EXTERNAL_REGISTRY_SNAPSHOT_V1, ExternalAdapterConfig, ExternalRegistryAdapter,
        ExternalRegistrySnapshotEntryV1, ExternalRegistrySnapshotV1, external_state_root,
    };
    use crate::{ChainTarget, FinalizedCheckpoint, RegistryChainAdapter};

    fn target() -> ChainTarget {
        ChainTarget {
            adapter: "external-fabric".into(),
            chain_identity: "fabric:channel-a:genesis-abc".into(),
            registry_locator: "fabric:channel-a/identity-registry".into(),
            registry_schema_hash:
                "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            evm: None,
        }
    }

    fn signed_snapshot_with(
        private: [u8; 32],
        issuer: &str,
        key_id: &str,
    ) -> (ExternalRegistrySnapshotV1, IssuerKeyRegistry) {
        let key = SigningKey::from_bytes(&private);
        let private_key = STANDARD.encode(key.to_bytes());
        let entries = vec![ExternalRegistrySnapshotEntryV1 {
            server_id: "operator/L01/r1".into(),
            resolver_id_key: resolver_id_key("operator/L01/r1"),
            object_hash: "0x3333333333333333333333333333333333333333333333333333333333333333"
                .into(),
            object_version: 1,
            valid_until: 2_000,
            status: "ACTIVE".into(),
            endpoint_keys: vec![
                "0x4444444444444444444444444444444444444444444444444444444444444444".into(),
            ],
        }];
        let mut snapshot = ExternalRegistrySnapshotV1 {
            schema_version: EXTERNAL_REGISTRY_SNAPSHOT_V1.into(),
            target: target(),
            checkpoint: FinalizedCheckpoint {
                number: 10,
                hash: "0x5555555555555555555555555555555555555555555555555555555555555555".into(),
            },
            generation: 1,
            state_root: external_state_root(&entries).unwrap(),
            root_status: "ACTIVE".into(),
            published_at: 900,
            valid_until: 2_000,
            issuer: issuer.into(),
            key_id: key_id.into(),
            entries,
            signature: None,
        };
        snapshot.signature = Some(ri_core::sign_ed25519(&snapshot, &private_key).unwrap());
        let mut issuer_keys = IssuerKeyRegistry::default();
        issuer_keys.insert(
            issuer,
            key_id,
            STANDARD.encode(key.verifying_key().to_bytes()),
        );
        (snapshot, issuer_keys)
    }

    fn signed_snapshot() -> (ExternalRegistrySnapshotV1, IssuerKeyRegistry) {
        signed_snapshot_with([9_u8; 32], "adapter-operator", "adapter-key-1")
    }

    #[derive(Clone)]
    struct ProtocolState {
        snapshot: Arc<ExternalRegistrySnapshotV1>,
        checkpoint: FinalizedCheckpoint,
    }

    async fn serve_snapshot(
        State(state): State<ProtocolState>,
    ) -> Json<ExternalRegistrySnapshotV1> {
        Json((*state.snapshot).clone())
    }

    async fn serve_block(
        Path(_number): Path<u64>,
        State(state): State<ProtocolState>,
    ) -> Json<FinalizedCheckpoint> {
        Json(state.checkpoint)
    }

    async fn spawn_protocol(
        snapshot: ExternalRegistrySnapshotV1,
        checkpoint: FinalizedCheckpoint,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/registry/snapshot", get(serve_snapshot))
            .route("/v1/blocks/{number}", get(serve_block))
            .with_state(ProtocolState {
                snapshot: Arc::new(snapshot),
                checkpoint,
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), task)
    }

    #[test]
    fn arbitrary_chain_snapshot_is_signed_and_pinned() {
        let (mut snapshot, issuer_keys) = signed_snapshot();
        let adapter = ExternalRegistryAdapter::new(ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints: vec!["http://127.0.0.1:18080/".into()],
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-1".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        })
        .unwrap();
        assert_eq!(
            adapter
                .validate_snapshot(&snapshot, &issuer_keys, 1_000)
                .unwrap()
                .len(),
            1
        );
        snapshot.generation = 2;
        assert!(
            adapter
                .validate_snapshot(&snapshot, &issuer_keys, 1_000)
                .is_err()
        );
    }

    #[test]
    fn signer_pin_expiration_and_key_rotation_fail_closed() {
        let (old_snapshot, mut keys) = signed_snapshot();
        let old_adapter = ExternalRegistryAdapter::new(ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints: vec!["http://127.0.0.1:18080/".into()],
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-1".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        })
        .unwrap();
        assert!(
            old_adapter
                .validate_snapshot(&old_snapshot, &keys, 1_000)
                .is_ok()
        );

        let (mut rotated_snapshot, rotated_keys) =
            signed_snapshot_with([10_u8; 32], "adapter-operator", "adapter-key-2");
        rotated_snapshot.generation = 2;
        rotated_snapshot.signature =
            Some(ri_core::sign_ed25519(&rotated_snapshot, &STANDARD.encode([10_u8; 32])).unwrap());
        keys.insert(
            "adapter-operator",
            "adapter-key-2",
            rotated_keys
                .get("adapter-operator", "adapter-key-2")
                .unwrap(),
        );
        let rotated_adapter = ExternalRegistryAdapter::new(ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints: vec!["http://127.0.0.1:18081/".into()],
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-2".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        })
        .unwrap();
        assert!(
            old_adapter
                .validate_snapshot(&rotated_snapshot, &keys, 1_000)
                .is_err()
        );
        assert!(
            rotated_adapter
                .validate_snapshot(&old_snapshot, &keys, 1_000)
                .is_err()
        );
        assert!(
            rotated_adapter
                .validate_snapshot(&rotated_snapshot, &keys, 1_000)
                .is_ok()
        );

        rotated_snapshot.valid_until = 999;
        rotated_snapshot.signature =
            Some(ri_core::sign_ed25519(&rotated_snapshot, &STANDARD.encode([10_u8; 32])).unwrap());
        assert!(
            rotated_adapter
                .validate_snapshot(&rotated_snapshot, &keys, 1_000)
                .is_err()
        );
    }

    #[test]
    fn snapshot_rejects_dynamic_upstream_fields() {
        let (snapshot, _) = signed_snapshot();
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["upstream_url"] = serde_json::json!("https://attacker.invalid/");
        assert!(serde_json::from_value::<ExternalRegistrySnapshotV1>(value).is_err());

        let (snapshot, _) = signed_snapshot();
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["target"]["rpc_url"] = serde_json::json!("https://attacker.invalid/");
        assert!(serde_json::from_value::<ExternalRegistrySnapshotV1>(value).is_err());
    }

    #[tokio::test]
    async fn protocol_client_does_not_follow_redirects() {
        async fn redirected(State(hits): State<Arc<AtomicUsize>>) -> &'static str {
            hits.fetch_add(1, Ordering::Relaxed);
            "must not be reached"
        }
        let destination_hits = Arc::new(AtomicUsize::new(0));
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        let destination_app = Router::new()
            .route("/v1/registry/snapshot", get(redirected))
            .with_state(Arc::clone(&destination_hits));
        let destination_task = tokio::spawn(async move {
            axum::serve(destination_listener, destination_app)
                .await
                .unwrap();
        });

        let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let location = format!("http://{destination_address}/v1/registry/snapshot");
        let redirect_app = Router::new().route(
            "/v1/registry/snapshot",
            get(move || {
                let location = location.clone();
                async move { Redirect::temporary(&location) }
            }),
        );
        let redirect_task = tokio::spawn(async move {
            axum::serve(redirect_listener, redirect_app).await.unwrap();
        });

        let client = super::ExternalProtocolClient::new(
            format!("http://{redirect_address}/"),
            std::time::Duration::from_secs(1),
            4_194_304,
            None,
            false,
        )
        .unwrap();
        assert!(client.snapshot().await.is_err());
        assert_eq!(destination_hits.load(Ordering::Relaxed), 0);
        redirect_task.abort();
        destination_task.abort();
    }

    #[tokio::test]
    async fn dual_external_protocol_endpoints_reconcile_and_detect_forks() {
        let (snapshot, issuer_keys) = signed_snapshot();
        let checkpoint = snapshot.checkpoint.clone();
        let (url_a, task_a) = spawn_protocol(snapshot.clone(), checkpoint.clone()).await;
        let (url_b, task_b) = spawn_protocol(snapshot.clone(), checkpoint.clone()).await;
        let adapter = ExternalRegistryAdapter::new(ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints: vec![url_a.clone(), url_b],
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-1".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        })
        .unwrap();
        let reconciled = adapter
            .read_snapshot(&[], &issuer_keys, 1_000)
            .await
            .unwrap();
        assert_eq!(reconciled.checkpoint, checkpoint);
        assert_eq!(reconciled.records.len(), 1);

        let divergent = FinalizedCheckpoint {
            number: checkpoint.number,
            hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        let (url_c, task_c) = spawn_protocol(snapshot, divergent).await;
        let forked = ExternalRegistryAdapter::new(ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints: vec![url_a, url_c],
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-1".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        })
        .unwrap();
        assert!(
            forked
                .read_snapshot(&[], &issuer_keys, 1_000)
                .await
                .is_err()
        );
        task_a.abort();
        task_b.abort();
        task_c.abort();
    }

    #[test]
    fn production_external_adapter_requires_two_https_endpoints() {
        let config = |endpoints| ExternalAdapterConfig {
            driver: "fabric".into(),
            endpoints,
            target: target(),
            signer_issuer: "adapter-operator".into(),
            signer_key_id: "adapter-key-1".into(),
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: true,
        };
        assert!(
            ExternalRegistryAdapter::new(config(vec!["https://adapter-a.example".into()])).is_err()
        );
        assert!(
            ExternalRegistryAdapter::new(config(vec![
                "https://adapter-a.example".into(),
                "https://adapter-b.example".into(),
            ]))
            .is_ok()
        );
        assert!(
            ExternalRegistryAdapter::new(config(vec![
                format!(
                    "https://{}@adapter-a.example",
                    ["test-user", "test-credential"].join(":")
                ),
                "https://adapter-b.example".into(),
            ]))
            .is_err()
        );
    }
}
