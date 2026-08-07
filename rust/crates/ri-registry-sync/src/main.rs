use std::collections::{BTreeSet, HashSet};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use ri_chain_adapter::{
    AdapterError, ChainTarget, EvmAdapterConfig, EvmRegistryAdapter, ExternalAdapterConfig,
    ExternalClientTlsMaterial, ExternalRegistryAdapter, NornAdapterConfig, NornClientTlsMaterial,
    NornRegistryAdapter, RegistryChainAdapter, registry_reference,
};
use ri_core::evidence::DNS_SERVER_IDENTITY_V2;
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, RegistryAdapterMetadataV2, object_hash,
    resolver_id_key, verify_ed25519,
};
use ri_store::EvidenceStore;
use serde::Deserialize;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_registry_sync=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    let adapter = settings.build_adapter()?;
    let target = adapter.target().clone();
    tracing::info!(
        adapter = %target.adapter,
        chain_identity = %target.chain_identity,
        registry_locator = %target.registry_locator,
        registry_schema_hash = %target.registry_schema_hash,
        "Registry Sync target pinned"
    );
    let store = EvidenceStore::open(&settings.database)?;
    let issuer_keys = load_issuer_keys(&settings.issuer_keys_file)?;
    let metrics = Arc::new(SyncMetrics::new(target));
    let monitoring_listener = tokio::net::TcpListener::bind(settings.monitoring_bind).await?;
    let _monitoring = tokio::spawn(serve_monitoring(
        monitoring_listener,
        Arc::clone(&metrics),
        registry_readiness_window(settings.poll_interval),
    ));

    loop {
        let result = match load_identities(&settings.identities_file) {
            Ok(identities) if !identities.is_empty() => {
                reconcile(adapter.as_ref(), &store, &issuer_keys, &identities).await
            }
            Ok(_) => Err("identity artifact contains no identities".into()),
            Err(error) => Err(error),
        };
        match &result {
            Ok(count) => {
                metrics
                    .records
                    .store(u64::try_from(*count).unwrap_or(u64::MAX), Ordering::Relaxed);
                metrics
                    .last_success_epoch
                    .store(unix_time(), Ordering::Relaxed);
                if let Some(checkpoint) = store.registry_checkpoint()? {
                    metrics
                        .finalized_block
                        .store(checkpoint.finalized_block, Ordering::Relaxed);
                    if let Ok(mut block_hash) = metrics.finalized_block_hash.write() {
                        *block_hash = checkpoint.finalized_block_hash;
                    }
                }
                tracing::info!(count, "finalized Registry snapshot reconciled");
            }
            Err(error) => {
                metrics.failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%error, "Registry reconciliation failed");
            }
        }
        if settings.once {
            return result.map(|_| ());
        }
        tokio::time::sleep(settings.poll_interval).await;
    }
}

struct SyncMetrics {
    last_success_epoch: AtomicI64,
    finalized_block: AtomicU64,
    finalized_block_hash: RwLock<String>,
    failures: AtomicU64,
    records: AtomicU64,
    target: ChainTarget,
}

impl SyncMetrics {
    fn new(target: ChainTarget) -> Self {
        Self {
            last_success_epoch: AtomicI64::new(0),
            finalized_block: AtomicU64::new(0),
            finalized_block_hash: RwLock::new(String::new()),
            failures: AtomicU64::new(0),
            records: AtomicU64::new(0),
            target,
        }
    }
}

#[derive(Clone)]
struct MonitoringState {
    metrics: Arc<SyncMetrics>,
    readiness_window: Duration,
}

fn registry_readiness_window(poll_interval: Duration) -> Duration {
    poll_interval
        .saturating_mul(30)
        .max(Duration::from_secs(60))
}

async fn serve_monitoring(
    listener: tokio::net::TcpListener,
    metrics: Arc<SyncMetrics>,
    readiness_window: Duration,
) -> Result<(), AnyError> {
    let bind = listener.local_addr()?;
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(sync_readiness))
        .route("/metrics", get(sync_metrics))
        .with_state(MonitoringState {
            metrics,
            readiness_window,
        });
    tracing::info!(%bind, "Registry Sync monitoring listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn sync_readiness(State(state): State<MonitoringState>) -> StatusCode {
    let last_success = state.metrics.last_success_epoch.load(Ordering::Relaxed);
    let window = i64::try_from(state.readiness_window.as_secs()).unwrap_or(i64::MAX);
    if last_success > 0 && unix_time().saturating_sub(last_success) <= window {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn sync_metrics(State(state): State<MonitoringState>) -> impl IntoResponse {
    let finalized_block_hash = state
        .metrics
        .finalized_block_hash
        .read()
        .map(|value| value.clone())
        .unwrap_or_default();
    let target = &state.metrics.target;
    let adapter = prometheus_label(&target.adapter);
    let chain_identity = prometheus_label(&target.chain_identity);
    let registry_locator = prometheus_label(&target.registry_locator);
    let registry_schema_hash = prometheus_label(&target.registry_schema_hash);
    let (evm_chain_id, evm_contract_address, evm_runtime_code_hash) =
        if let RegistryAdapterMetadataV2::Evm {
            chain_id,
            contract_address,
            runtime_code_hash,
        } = &target.adapter_metadata
        {
            (
                chain_id.to_string(),
                prometheus_label(contract_address),
                prometheus_label(runtime_code_hash),
            )
        } else {
            (String::new(), String::new(), String::new())
        };
    let finalized_block_hash = prometheus_label(&finalized_block_hash);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        format!(
            concat!(
                "# TYPE resolver_identity_registry_last_success_epoch gauge\n",
                "resolver_identity_registry_last_success_epoch {}\n",
                "# TYPE resolver_identity_registry_finalized_block gauge\n",
                "resolver_identity_registry_finalized_block {}\n",
                "# TYPE resolver_identity_registry_failures_total counter\n",
                "resolver_identity_registry_failures_total {}\n",
                "# TYPE resolver_identity_registry_records gauge\n",
                "resolver_identity_registry_records {}\n",
                "# TYPE resolver_identity_registry_target_info gauge\n",
                "resolver_identity_registry_target_info{{adapter=\"{}\",chain_identity=\"{}\",registry_locator=\"{}\",registry_schema_hash=\"{}\",evm_chain_id=\"{}\",evm_contract_address=\"{}\",evm_runtime_code_hash=\"{}\"}} 1\n",
                "# TYPE resolver_identity_registry_finalized_info gauge\n",
                "resolver_identity_registry_finalized_info{{block_hash=\"{}\"}} 1\n"
            ),
            state.metrics.last_success_epoch.load(Ordering::Relaxed),
            state.metrics.finalized_block.load(Ordering::Relaxed),
            state.metrics.failures.load(Ordering::Relaxed),
            state.metrics.records.load(Ordering::Relaxed),
            adapter,
            chain_identity,
            registry_locator,
            registry_schema_hash,
            evm_chain_id,
            evm_contract_address,
            evm_runtime_code_hash,
            finalized_block_hash
        ),
    )
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}

async fn reconcile(
    adapter: &dyn RegistryChainAdapter,
    store: &EvidenceStore,
    issuer_keys: &IssuerKeyRegistry,
    identities: &[DnsServerIdentityV2],
) -> Result<usize, AnyError> {
    let now = unix_time();
    for identity in identities {
        validate_identity_artifact(identity, issuer_keys, now)
            .map_err(|error| format!("{}: {error}", identity.server_id))?;
    }
    let snapshot = adapter.read_snapshot(identities, issuer_keys, now).await?;
    if let Some(checkpoint) = store.registry_checkpoint()? {
        if snapshot.checkpoint.number < checkpoint.finalized_block {
            return Err(format!(
                "finalized block rollback: stored {}, received {}",
                checkpoint.finalized_block, snapshot.checkpoint.number
            )
            .into());
        }
        let canonical_checkpoint_hash = adapter.block_hash(checkpoint.finalized_block).await?;
        if canonical_checkpoint_hash != checkpoint.finalized_block_hash {
            return Err("stored finalized checkpoint is no longer canonical".into());
        }
    }

    let mut records = Vec::with_capacity(identities.len());
    for identity in identities {
        let record = snapshot
            .records
            .get(&identity.server_id)
            .ok_or_else(|| format!("Registry has no record for {}", identity.server_id))?
            .clone();
        if record.state_root != snapshot.state_root {
            return Err(format!(
                "{}: Registry record state root differs from the snapshot root",
                identity.server_id
            )
            .into());
        }
        validate_registry_record(identity, &record)
            .map_err(|error| format!("{}: {error}", identity.server_id))?;
        records.push((
            identity.clone(),
            registry_reference(
                adapter.target(),
                &snapshot.checkpoint,
                snapshot.generation,
                record,
            ),
        ));
    }
    let confirmed_hash = adapter.block_hash(snapshot.checkpoint.number).await?;
    if confirmed_hash != snapshot.checkpoint.hash {
        return Err("finalized block hash changed during reconciliation".into());
    }
    // Capture the completion timestamp AFTER all async reads and validations
    // succeed, so the heartbeat reflects when reconciliation actually finished,
    // not when it started.  The Norn adapter read can take tens of seconds, and
    // using the start timestamp would cause the Agent to immediately consider
    // the registry snapshot stale.
    let reconciled_at = unix_time();
    store.apply_registry_snapshot(&records, reconciled_at)?;
    Ok(records.len())
}

fn validate_identity_artifact(
    identity: &DnsServerIdentityV2,
    issuer_keys: &IssuerKeyRegistry,
    now: i64,
) -> Result<(), AnyError> {
    let issuer_key = issuer_keys
        .get(&identity.issuer, &identity.key_id)
        .ok_or("identity issuer key is not trusted")?;
    verify_ed25519(identity, issuer_key)?;
    if !identity.active_at(now) {
        return Err("identity artifact is not currently active".into());
    }
    Ok(())
}

fn validate_registry_record(
    identity: &DnsServerIdentityV2,
    record: &ri_chain_adapter::RegistryRecord,
) -> Result<(), AnyError> {
    let expected_hash = object_hash(identity)?;
    let expected_resolver_key = resolver_id_key(&identity.server_id);
    if record.resolver_id_key != expected_resolver_key
        || record.object_hash != expected_hash
        || record.object_version != identity.object_version
        || record.valid_until != identity.valid_until
        || record.resolver_status != "ACTIVE"
        || record.root_status != "ACTIVE"
    {
        return Err("Registry record does not match the signed identity".into());
    }
    let expected_endpoints = identity
        .endpoints
        .iter()
        .map(|endpoint| endpoint.registry_key())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual_endpoints = record
        .endpoint_owners
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_endpoints != expected_endpoints
        || record
            .endpoint_owners
            .values()
            .any(|owner| owner != &expected_resolver_key)
    {
        return Err("Registry endpoint bindings do not match the signed identity".into());
    }
    Ok(())
}

enum AdapterSettings {
    Evm(EvmAdapterConfig),
    Norn(NornAdapterConfig),
    External(ExternalAdapterConfig),
}

struct Settings {
    adapter: AdapterSettings,
    database: PathBuf,
    identities_file: PathBuf,
    issuer_keys_file: PathBuf,
    poll_interval: Duration,
    once: bool,
    monitoring_bind: SocketAddr,
}

impl Settings {
    fn from_env() -> Result<Self, AnyError> {
        let production = parse_environment(&required("RI_ENVIRONMENT")?)?;
        let request_timeout = Duration::from_millis(parse_u64("RI_RPC_TIMEOUT_MS", 5_000)?);
        let max_response_bytes =
            usize::try_from(parse_u64("RI_RPC_MAX_RESPONSE_BYTES", 4_194_304)?)?;
        let poll_interval =
            Duration::from_millis(parse_u64("RI_REGISTRY_POLL_INTERVAL_MS", 2_000)?);
        if request_timeout.is_zero() || poll_interval.is_zero() || max_response_bytes < 1_024 {
            return Err("Registry time and response limits are invalid".into());
        }
        let adapter_name = required("RI_CHAIN_ADAPTER")?;
        let adapter = match adapter_name.as_str() {
            "evm" => AdapterSettings::Evm(EvmAdapterConfig {
                rpc_url: required_any(&["RI_CHAIN_RPC_URL", "RI_WEB3_RPC_URL"])?,
                chain_id: required_any(&["RI_CHAIN_ID", "RI_WEB3_CHAIN_ID"])?.parse()?,
                contract_address: required_any(&[
                    "RI_CHAIN_REGISTRY_ADDRESS",
                    "RI_REGISTRY_CONTRACT_ADDRESS",
                ])?,
                runtime_code_hash: required_any(&[
                    "RI_CHAIN_REGISTRY_SCHEMA_HASH",
                    "RI_REGISTRY_CODE_HASH",
                ])?,
                fallback_confirmations: parse_u64_any(
                    &[
                        "RI_CHAIN_CONFIRMATIONS",
                        "RI_REGISTRY_FALLBACK_CONFIRMATIONS",
                    ],
                    12,
                )?,
                request_timeout,
                max_response_bytes,
                production,
            }),
            "norn" => AdapterSettings::Norn(NornAdapterConfig {
                rpc_urls: parse_urls(&required_any(&["RI_NORN_RPC_URLS", "RI_CHAIN_RPC_URLS"])?)?,
                chain_id: required("RI_CHAIN_ID")?.parse()?,
                genesis_block_hash: required("RI_NORN_GENESIS_BLOCK_HASH")?,
                registry_address: required_any(&[
                    "RI_CHAIN_REGISTRY_ADDRESS",
                    "RI_NORN_REGISTRY_ADDRESS",
                ])?,
                registry_key: required("RI_NORN_REGISTRY_KEY")?,
                registry_schema_hash: required("RI_CHAIN_REGISTRY_SCHEMA_HASH")?,
                snapshot_signer_issuer: required("RI_NORN_SIGNER_ISSUER")?,
                snapshot_signer_key_id: required("RI_NORN_SIGNER_KEY_ID")?,
                confirmations: parse_u64_any(
                    &["RI_CHAIN_CONFIRMATIONS", "RI_NORN_CONFIRMATIONS"],
                    12,
                )?,
                registry_start_height: parse_u64("RI_NORN_REGISTRY_START_HEIGHT", 0)?,
                max_scan_blocks: parse_u64("RI_NORN_MAX_SCAN_BLOCKS", 10_000)?,
                request_timeout,
                max_response_bytes,
                tls: optional_norn_tls_material()?,
                production,
            }),
            "external" => {
                let driver = required("RI_EXTERNAL_DRIVER")?;
                let schema_hash = required("RI_CHAIN_REGISTRY_SCHEMA_HASH")?;
                let signer_issuer = required("RI_EXTERNAL_SIGNER_ISSUER")?;
                let signer_key_id = required("RI_EXTERNAL_SIGNER_KEY_ID")?;
                AdapterSettings::External(ExternalAdapterConfig {
                    endpoints: parse_urls(&required_any(&[
                        "RI_EXTERNAL_ADAPTER_URLS",
                        "RI_CHAIN_RPC_URLS",
                    ])?)?,
                    target: ChainTarget {
                        adapter: "external".into(),
                        chain_identity: required("RI_CHAIN_IDENTITY")?,
                        registry_locator: required("RI_CHAIN_REGISTRY_LOCATOR")?,
                        registry_schema_hash: schema_hash,
                        adapter_metadata: RegistryAdapterMetadataV2::External {
                            driver: driver.clone(),
                            snapshot_signer_issuer: signer_issuer.clone(),
                            snapshot_signer_key_id: signer_key_id.clone(),
                        },
                    },
                    driver,
                    signer_issuer,
                    signer_key_id,
                    request_timeout,
                    max_response_bytes,
                    tls: optional_external_tls_material()?,
                    production,
                })
            }
            _ => {
                return Err(format!(
                    "unsupported RI_CHAIN_ADAPTER {adapter_name}; expected evm, norn, or external"
                )
                .into());
            }
        };
        Ok(Self {
            adapter,
            database: required("RI_DATABASE")?.into(),
            identities_file: required("RI_IDENTITIES_FILE")?.into(),
            issuer_keys_file: required("RI_ISSUER_KEYS_FILE")?.into(),
            poll_interval,
            once: env::var("RI_REGISTRY_SYNC_ONCE").is_ok_and(|value| value == "true"),
            monitoring_bind: env::var("RI_REGISTRY_MONITORING_BIND")
                .unwrap_or_else(|_| "127.0.0.1:9109".into())
                .parse()?,
        })
    }

    fn build_adapter(&self) -> Result<Box<dyn RegistryChainAdapter>, AdapterError> {
        match &self.adapter {
            AdapterSettings::Evm(config) => Ok(Box::new(EvmRegistryAdapter::new(config.clone())?)),
            AdapterSettings::Norn(config) => {
                Ok(Box::new(NornRegistryAdapter::new(config.clone())?))
            }
            AdapterSettings::External(config) => {
                Ok(Box::new(ExternalRegistryAdapter::new(config.clone())?))
            }
        }
    }
}

#[derive(Deserialize)]
struct IdentityFile {
    identities: Vec<DnsServerIdentityV2>,
}

#[derive(Deserialize)]
struct IssuerKeyFile {
    keys: Vec<IssuerKeyRecord>,
}

#[derive(Deserialize)]
struct IssuerKeyRecord {
    issuer: String,
    key_id: String,
    algorithm: String,
    public_key: String,
}

fn load_identities(path: &Path) -> Result<Vec<DnsServerIdentityV2>, AnyError> {
    let identities = serde_json::from_slice::<IdentityFile>(&std::fs::read(path)?)?.identities;
    if identities.is_empty() {
        return Err("identity artifact contains no identities".into());
    }
    let mut server_ids = HashSet::new();
    let mut endpoints = HashSet::new();
    for identity in &identities {
        if identity.schema_version != DNS_SERVER_IDENTITY_V2
            || identity.server_id.is_empty()
            || identity.operator_id.is_empty()
            || identity.issuer.is_empty()
            || identity.key_id.is_empty()
            || identity.object_version == 0
            || identity.valid_from >= identity.valid_until
            || identity.endpoints.is_empty()
            || identity.endpoints.len() > 32
        {
            return Err(format!(
                "identity {} has invalid required fields",
                identity.server_id
            )
            .into());
        }
        if !server_ids.insert(identity.server_id.clone()) {
            return Err(format!("duplicate server_id {}", identity.server_id).into());
        }
        if identity.anycast != identity.anycast_service_id.is_some() {
            return Err(format!(
                "identity {} has inconsistent anycast fields",
                identity.server_id
            )
            .into());
        }
        if let Some(agent) = &identity.agent
            && (agent.key_id.is_empty()
                || !agent.algorithm.eq_ignore_ascii_case("ed25519")
                || agent.public_key.is_empty()
                || agent.service_url.as_deref().is_none_or(str::is_empty))
        {
            return Err(format!(
                "identity {} has an invalid Agent binding",
                identity.server_id
            )
            .into());
        }
        for endpoint in &identity.endpoints {
            let key = endpoint.cache_key()?;
            if !endpoints.insert(key.clone()) {
                return Err(format!("duplicate endpoint {key}").into());
            }
        }
    }
    Ok(identities)
}

fn load_issuer_keys(path: &Path) -> Result<IssuerKeyRegistry, AnyError> {
    let file: IssuerKeyFile = serde_json::from_slice(&std::fs::read(path)?)?;
    if file.keys.is_empty() {
        return Err("issuer key bundle is empty".into());
    }
    let mut registry = IssuerKeyRegistry::default();
    let mut key_ids = HashSet::new();
    for key in file.keys {
        if key.issuer.is_empty()
            || key.key_id.is_empty()
            || key.public_key.is_empty()
            || !key.algorithm.eq_ignore_ascii_case("ed25519")
        {
            return Err("issuer key record is invalid".into());
        }
        if !key_ids.insert((key.issuer.clone(), key.key_id.clone())) {
            return Err("issuer key bundle contains a duplicate issuer/key_id".into());
        }
        registry.insert(key.issuer, key.key_id, key.public_key);
    }
    Ok(registry)
}

fn required(name: &str) -> Result<String, AnyError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

fn required_any(names: &[&str]) -> Result<String, AnyError> {
    let configured = names
        .iter()
        .filter_map(|name| {
            env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| (*name, value))
        })
        .collect::<Vec<_>>();
    let Some((_, first)) = configured.first() else {
        return Err(format!("one of {} is required", names.join(", ")).into());
    };
    if configured.iter().any(|(_, value)| value != first) {
        return Err(format!(
            "conflicting compatibility variables: {}",
            configured
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into());
    }
    Ok(first.clone())
}

fn parse_environment(value: &str) -> Result<bool, AnyError> {
    match value {
        "production" => Ok(true),
        "development" | "test" => Ok(false),
        _ => Err("RI_ENVIRONMENT must be production, development, or test".into()),
    }
}

fn parse_u64(name: &str, default: u64) -> Result<u64, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_u64_any(names: &[&str], default: u64) -> Result<u64, AnyError> {
    if names
        .iter()
        .any(|name| env::var(name).is_ok_and(|value| !value.trim().is_empty()))
    {
        return Ok(required_any(names)?.parse()?);
    }
    Ok(default)
}

fn parse_urls(value: &str) -> Result<Vec<String>, AnyError> {
    let urls = value
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if urls.is_empty() {
        return Err("RPC URL list is empty".into());
    }
    Ok(urls)
}

fn optional_norn_tls_material() -> Result<Option<NornClientTlsMaterial>, AnyError> {
    let names = [
        "RI_NORN_TLS_CA_FILE",
        "RI_NORN_TLS_CLIENT_CERT_FILE",
        "RI_NORN_TLS_CLIENT_KEY_FILE",
    ];
    let paths = names
        .iter()
        .map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
        .collect::<Vec<_>>();
    if paths.iter().all(Option::is_none) {
        return Ok(None);
    }
    if paths.iter().any(Option::is_none) {
        return Err(format!("{} must be configured together", names.join(", ")).into());
    }
    Ok(Some(NornClientTlsMaterial {
        ca_certificate_pem: std::fs::read(paths[0].as_deref().unwrap_or_default())?,
        client_certificate_pem: std::fs::read(paths[1].as_deref().unwrap_or_default())?,
        client_private_key_pem: std::fs::read(paths[2].as_deref().unwrap_or_default())?,
    }))
}

fn optional_external_tls_material() -> Result<Option<ExternalClientTlsMaterial>, AnyError> {
    let names = [
        "RI_EXTERNAL_TLS_CA_FILE",
        "RI_EXTERNAL_TLS_CLIENT_CERT_FILE",
        "RI_EXTERNAL_TLS_CLIENT_KEY_FILE",
    ];
    let paths = names
        .iter()
        .map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
        .collect::<Vec<_>>();
    if paths.iter().all(Option::is_none) {
        return Ok(None);
    }
    if paths.iter().any(Option::is_none) {
        return Err(format!("{} must be configured together", names.join(", ")).into());
    }
    Ok(Some(ExternalClientTlsMaterial {
        ca_certificate_pem: std::fs::read(paths[0].as_deref().unwrap_or_default())?,
        client_certificate_pem: std::fs::read(paths[1].as_deref().unwrap_or_default())?,
        client_private_key_pem: std::fs::read(paths[2].as_deref().unwrap_or_default())?,
    }))
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ri_chain_adapter::{
        AdapterError, AdapterResult, ChainSnapshot, ChainTarget, FinalizedCheckpoint,
        RegistryChainAdapter, RegistryRecord,
    };
    use ri_core::{
        AgentBindingV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole, IssuerKeyRegistry,
        RegistryAdapterMetadataV2, RegistryFinalityTypeV2, ed25519_public_key_b64, object_hash,
        sign_ed25519,
    };
    use ri_store::EvidenceStore;

    use super::{parse_urls, prometheus_label, reconcile, registry_readiness_window};

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    /// Deterministic 32-byte Ed25519 seed from a start byte.
    fn key(start: u8) -> String {
        STANDARD.encode((start..start + 32).collect::<Vec<_>>())
    }

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn test_issuer_keys(issuer_private: &str) -> IssuerKeyRegistry {
        let mut keys = IssuerKeyRegistry::default();
        keys.insert(
            "test-issuer",
            "issuer-key-1",
            ed25519_public_key_b64(issuer_private).unwrap(),
        );
        keys
    }

    fn test_identity(
        server_id: &str,
        role: DnsServerRole,
        issuer_private: &str,
        agent_private: &str,
    ) -> DnsServerIdentityV2 {
        let now = unix_now();
        let mut identity = DnsServerIdentityV2 {
            schema_version: ri_core::evidence::DNS_SERVER_IDENTITY_V2.into(),
            server_id: server_id.into(),
            operator_id: "test-operator".into(),
            role,
            endpoints: vec![DnsEndpoint {
                transport: "udp".into(),
                ip: Some("127.0.0.1".into()),
                port: Some(5300),
                uri: None,
                server_name: None,
                alpn: vec![],
                endpoint_id: None,
            }],
            anycast: false,
            anycast_service_id: None,
            agent: Some(AgentBindingV2 {
                algorithm: "ed25519".into(),
                key_id: format!("{server_id}-agent-key"),
                public_key: ed25519_public_key_b64(agent_private).unwrap(),
                service_url: Some("https://127.0.0.1:8443".into()),
            }),
            valid_from: now - 60,
            valid_until: now + 3600,
            object_version: 1,
            status: "ACTIVE".into(),
            issuer: "test-issuer".into(),
            key_id: "issuer-key-1".into(),
            signature: None,
        };
        identity.signature = Some(sign_ed25519(&identity, issuer_private).unwrap());
        identity
    }

    /// A mock chain adapter that introduces a configurable delay before returning
    /// a fixed snapshot.  Used to verify that the heartbeat reflects completion
    /// time, not start time.
    struct MockDelayedAdapter {
        delay: Duration,
        succeed: bool,
    }

    #[async_trait]
    impl RegistryChainAdapter for MockDelayedAdapter {
        fn target(&self) -> &ChainTarget {
            // Leaked for test simplicity — tests are short-lived.
            static TARGET: std::sync::LazyLock<ChainTarget> =
                std::sync::LazyLock::new(|| ChainTarget {
                    adapter: "mock".into(),
                    chain_identity: "mock:1".into(),
                    registry_locator: "mock:0x1".into(),
                    registry_schema_hash: "0x00".into(),
                    adapter_metadata: RegistryAdapterMetadataV2::External {
                        driver: "mock".into(),
                        snapshot_signer_issuer: "test-issuer".into(),
                        snapshot_signer_key_id: "issuer-key-1".into(),
                    },
                });
            &TARGET
        }

        async fn read_snapshot(
            &self,
            identities: &[DnsServerIdentityV2],
            _issuer_keys: &IssuerKeyRegistry,
            _now: i64,
        ) -> AdapterResult<ChainSnapshot> {
            tokio::time::sleep(self.delay).await;
            if !self.succeed {
                return Err(AdapterError::from("mock adapter configured to fail"));
            }
            let mut records = BTreeMap::new();
            for identity in identities {
                let hash = object_hash(identity).unwrap();
                records.insert(
                    identity.server_id.clone(),
                    RegistryRecord {
                        resolver_id_key: ri_core::resolver_id_key(&identity.server_id),
                        object_hash: hash,
                        state_root:
                            "0x5555555555555555555555555555555555555555555555555555555555555555"
                                .into(),
                        object_version: identity.object_version,
                        valid_until: identity.valid_until,
                        resolver_status: "ACTIVE".into(),
                        root_status: "ACTIVE".into(),
                        endpoint_owners: identity
                            .endpoints
                            .iter()
                            .map(|ep| {
                                (
                                    ep.registry_key().unwrap(),
                                    ri_core::resolver_id_key(&identity.server_id),
                                )
                            })
                            .collect(),
                    },
                );
            }
            Ok(ChainSnapshot {
                checkpoint: FinalizedCheckpoint {
                    number: 100,
                    hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .into(),
                    finality_type: RegistryFinalityTypeV2::EvmFinalized,
                },
                state_root: "0x5555555555555555555555555555555555555555555555555555555555555555"
                    .into(),
                generation: 1,
                records,
            })
        }

        async fn block_hash(&self, _number: u64) -> AdapterResult<String> {
            Ok("0x1111111111111111111111111111111111111111111111111111111111111111".into())
        }
    }

    // ---------------------------------------------------------------------------
    // Heartbeat timing tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn heartbeat_reflects_completion_time_not_start_time() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("evidence.db");
        let store = EvidenceStore::open(&db_path).unwrap();
        // Seed an initial heartbeat well in the past so we can detect the update.
        store.mark_registry_sync_success(1).unwrap();

        let issuer_private = key(1);
        let issuer_keys = test_issuer_keys(&issuer_private);
        let agent_private = key(33);
        let identity = test_identity(
            "operator/L01/test",
            DnsServerRole::Recursive,
            &issuer_private,
            &agent_private,
        );

        // Adapter with a 3-second delay.
        let adapter = MockDelayedAdapter {
            delay: Duration::from_secs(3),
            succeed: true,
        };

        let before = unix_now();
        let result = reconcile(&adapter, &store, &issuer_keys, &[identity]).await;
        let after = unix_now();

        assert!(
            result.is_ok(),
            "reconcile should succeed: {:?}",
            result.err()
        );
        let heartbeat = store.registry_last_success_epoch().unwrap();

        // The heartbeat must be close to the completion time (within 1 second),
        // NOT close to the start time which is at least 3 seconds earlier.
        let diff_from_after = (after - heartbeat).abs();
        let diff_from_before = (heartbeat - before).abs();

        assert!(
            diff_from_after <= 1,
            "heartbeat {heartbeat} is {diff_from_after}s from completion time {after} (should be ≤1s)"
        );
        assert!(
            diff_from_before >= 3,
            "heartbeat {heartbeat} is only {diff_from_before}s from start time {before} (should be ≥3s with 3s delay)"
        );
    }

    #[tokio::test]
    async fn failed_sync_does_not_refresh_heartbeat() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("evidence.db");
        let store = EvidenceStore::open(&db_path).unwrap();

        // Set a known initial heartbeat.
        let initial_epoch = 100_000;
        store.mark_registry_sync_success(initial_epoch).unwrap();

        let issuer_private = key(1);
        let issuer_keys = test_issuer_keys(&issuer_private);
        let agent_private = key(33);
        let identity = test_identity(
            "operator/L01/test",
            DnsServerRole::Recursive,
            &issuer_private,
            &agent_private,
        );

        // Adapter that will fail on read_snapshot.
        let adapter = MockDelayedAdapter {
            delay: Duration::from_millis(10),
            succeed: false,
        };

        let result = reconcile(&adapter, &store, &issuer_keys, &[identity]).await;
        assert!(result.is_err(), "reconcile should have failed");

        let heartbeat = store.registry_last_success_epoch().unwrap();
        assert_eq!(
            heartbeat, initial_epoch,
            "heartbeat must not change on failed sync: was {initial_epoch}, now {heartbeat}"
        );
    }

    #[test]
    fn readiness_window_covers_long_reconciliation_cycles() {
        assert_eq!(
            registry_readiness_window(Duration::from_secs(2)),
            Duration::from_secs(60)
        );
        assert_eq!(
            registry_readiness_window(Duration::from_secs(5)),
            Duration::from_secs(150)
        );
    }

    #[test]
    fn rpc_url_lists_are_trimmed_and_empty_items_are_removed() {
        assert_eq!(
            parse_urls("https://a.example, https://b.example,").unwrap(),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(parse_urls(" , ").is_err());
    }

    #[test]
    fn prometheus_target_labels_are_escaped() {
        assert_eq!(
            prometheus_label("chain\\name\"\nnext"),
            r#"chain\\name\"\nnext"#
        );
    }
}
