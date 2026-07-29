use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::StreamExt;
use ri_core::evidence::DNS_SERVER_IDENTITY_V2;
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, RegistryReferenceV2, object_hash, resolver_id_key,
    verify_ed25519,
};
use ri_store::EvidenceStore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

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
    let client = RpcClient::new(
        settings.rpc_url.clone(),
        settings.request_timeout,
        settings.production,
        settings.max_rpc_response_bytes,
    )?;
    let store = EvidenceStore::open(&settings.database)?;
    let issuer_keys = load_issuer_keys(&settings.issuer_keys_file)?;
    let metrics = Arc::new(SyncMetrics::default());
    let monitoring_listener = tokio::net::TcpListener::bind(settings.monitoring_bind).await?;
    let _monitoring = tokio::spawn(serve_monitoring(
        monitoring_listener,
        Arc::clone(&metrics),
        settings.poll_interval.saturating_mul(3),
    ));

    loop {
        let result = match load_identities(&settings.identities_file) {
            Ok(identities) if !identities.is_empty() => {
                reconcile(&settings, &client, &store, &issuer_keys, &identities).await
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

#[derive(Default)]
struct SyncMetrics {
    last_success_epoch: AtomicI64,
    finalized_block: AtomicU64,
    failures: AtomicU64,
    records: AtomicU64,
}

#[derive(Clone)]
struct MonitoringState {
    metrics: Arc<SyncMetrics>,
    readiness_window: Duration,
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
                "resolver_identity_registry_records {}\n"
            ),
            state.metrics.last_success_epoch.load(Ordering::Relaxed),
            state.metrics.finalized_block.load(Ordering::Relaxed),
            state.metrics.failures.load(Ordering::Relaxed),
            state.metrics.records.load(Ordering::Relaxed)
        ),
    )
}

async fn reconcile(
    settings: &Settings,
    client: &RpcClient,
    store: &EvidenceStore,
    issuer_keys: &IssuerKeyRegistry,
    identities: &[DnsServerIdentityV2],
) -> Result<usize, AnyError> {
    let finalized = finalized_block(settings, client).await?;
    let block_tag = format!("0x{:x}", finalized.number);
    verify_chain(settings, client, &block_tag).await?;
    if let Some(checkpoint) = store.registry_checkpoint()? {
        if finalized.number < checkpoint.finalized_block {
            return Err(format!(
                "finalized block rollback: stored {}, received {}",
                checkpoint.finalized_block, finalized.number
            )
            .into());
        }
        let canonical_checkpoint_hash = block_hash(client, checkpoint.finalized_block).await?;
        if canonical_checkpoint_hash != checkpoint.finalized_block_hash {
            return Err("stored finalized checkpoint is no longer canonical".into());
        }
    }
    let mut records = Vec::with_capacity(identities.len());
    for identity in identities {
        let reference = reconcile_identity(
            settings,
            client,
            issuer_keys,
            identity,
            &finalized,
            &block_tag,
        )
        .await
        .map_err(|error| format!("{}: {error}", identity.server_id))?;
        records.push((identity.clone(), reference));
    }
    let confirmed_hash = block_hash(client, finalized.number).await?;
    if confirmed_hash != finalized.hash {
        return Err("finalized block hash changed during reconciliation".into());
    }
    store.apply_registry_snapshot(&records, unix_time())?;
    Ok(records.len())
}

async fn reconcile_identity(
    settings: &Settings,
    client: &RpcClient,
    issuer_keys: &IssuerKeyRegistry,
    identity: &DnsServerIdentityV2,
    finalized: &FinalizedBlock,
    block_tag: &str,
) -> Result<RegistryReferenceV2, AnyError> {
    let issuer_key = issuer_keys
        .get(&identity.issuer, &identity.key_id)
        .ok_or("identity issuer key is not trusted")?;
    verify_ed25519(identity, issuer_key)?;
    if !identity.active_at(unix_time()) {
        return Err("identity artifact is not currently active".into());
    }
    let expected_hash = object_hash(identity)?;
    let expected_resolver_key = resolver_id_key(&identity.server_id);
    let anchor = get_resolver_anchor(
        client,
        &settings.contract_address,
        &expected_resolver_key,
        block_tag,
    )
    .await?;
    if anchor.resolver_id_key != expected_resolver_key
        || anchor.object_hash != expected_hash
        || anchor.object_version != identity.object_version
        || anchor.valid_until != identity.valid_until
        || anchor.status != "ACTIVE"
    {
        return Err("on-chain resolver anchor does not match the signed identity".into());
    }
    let root_status = get_status(
        client,
        &settings.contract_address,
        "getRootStatus(bytes32)",
        &anchor.state_root,
        block_tag,
    )
    .await?;
    if root_status != "ACTIVE" {
        return Err(format!("identity root status is {root_status}").into());
    }
    for endpoint in &identity.endpoints {
        let endpoint_key = endpoint.registry_key()?;
        let bound_resolver = get_bytes32(
            client,
            &settings.contract_address,
            "lookupResolverByEndpoint(bytes32)",
            &endpoint_key,
            block_tag,
        )
        .await?;
        if bound_resolver != expected_resolver_key {
            return Err(format!(
                "endpoint {} is not bound to the identity",
                endpoint.cache_key()?
            )
            .into());
        }
    }
    Ok(RegistryReferenceV2 {
        chain_id: settings.chain_id,
        contract_address: settings.contract_address.clone(),
        contract_code_hash: settings.contract_code_hash.clone(),
        finalized_block: finalized.number,
        finalized_block_hash: finalized.hash.clone(),
        state_root: anchor.state_root,
        object_hash: anchor.object_hash,
        object_version: anchor.object_version,
        resolver_status: anchor.status,
        root_status,
        endpoint_binding_status: "MATCHED".into(),
        snapshot_generation: finalized.number,
    })
}

async fn verify_chain(
    settings: &Settings,
    client: &RpcClient,
    block_tag: &str,
) -> Result<(), AnyError> {
    let chain_id = parse_quantity(&client.call("eth_chainId", json!([])).await?)?;
    if chain_id != settings.chain_id {
        return Err(format!(
            "chain ID mismatch: expected {}, got {chain_id}",
            settings.chain_id
        )
        .into());
    }
    let code = client
        .call("eth_getCode", json!([settings.contract_address, block_tag]))
        .await?
        .as_str()
        .ok_or("eth_getCode returned a non-string")?
        .to_owned();
    let code_bytes = decode_hex(&code)?;
    if code_bytes.is_empty() {
        return Err("Registry address has no runtime code".into());
    }
    let actual_code_hash = format!("0x{}", hex::encode(Keccak256::digest(code_bytes)));
    if actual_code_hash != settings.contract_code_hash {
        return Err(format!(
            "Registry runtime code hash mismatch: expected {}, got {actual_code_hash}",
            settings.contract_code_hash
        )
        .into());
    }
    Ok(())
}

async fn finalized_block(
    settings: &Settings,
    client: &RpcClient,
) -> Result<FinalizedBlock, AnyError> {
    if let Ok(value) = client
        .call("eth_getBlockByNumber", json!(["finalized", false]))
        .await
        && !value.is_null()
    {
        return parse_block(&value);
    }
    let head = parse_quantity(&client.call("eth_blockNumber", json!([])).await?)?;
    let number = head
        .checked_sub(settings.fallback_confirmations)
        .ok_or("chain head has fewer blocks than fallback confirmations")?;
    let value = client
        .call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )
        .await?;
    parse_block(&value)
}

async fn get_resolver_anchor(
    client: &RpcClient,
    contract: &str,
    resolver_key: &str,
    block_tag: &str,
) -> Result<ResolverAnchor, AnyError> {
    let output = eth_call(
        client,
        contract,
        "getResolverAnchor(bytes32)",
        resolver_key,
        block_tag,
    )
    .await?;
    if output.len() != 32 * 6 {
        return Err("getResolverAnchor returned an invalid ABI payload".into());
    }
    Ok(ResolverAnchor {
        resolver_id_key: word_hex(&output, 0),
        object_hash: word_hex(&output, 1),
        state_root: word_hex(&output, 2),
        object_version: word_u64(&output, 3)?,
        valid_until: i64::try_from(word_u64(&output, 4)?)
            .map_err(|_| "resolver validUntil exceeds i64")?,
        status: status_name(word_u64(&output, 5)?)?.into(),
    })
}

async fn get_status(
    client: &RpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> Result<String, AnyError> {
    let output = eth_call(client, contract, function, argument, block_tag).await?;
    if output.len() != 32 {
        return Err("status call returned an invalid ABI payload".into());
    }
    Ok(status_name(word_u64(&output, 0)?)?.into())
}

async fn get_bytes32(
    client: &RpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> Result<String, AnyError> {
    let output = eth_call(client, contract, function, argument, block_tag).await?;
    if output.len() != 32 {
        return Err("bytes32 call returned an invalid ABI payload".into());
    }
    Ok(word_hex(&output, 0))
}

async fn eth_call(
    client: &RpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> Result<Vec<u8>, AnyError> {
    let selector = function_selector(function);
    let argument = decode_bytes32(argument)?;
    let data = format!("0x{}{}", hex::encode(selector), hex::encode(argument));
    let output = client
        .call(
            "eth_call",
            json!([{"to": contract, "data": data}, block_tag]),
        )
        .await?;
    decode_hex(output.as_str().ok_or("eth_call returned a non-string")?)
}

#[derive(Debug)]
struct ResolverAnchor {
    resolver_id_key: String,
    object_hash: String,
    state_root: String,
    object_version: u64,
    valid_until: i64,
    status: String,
}

struct FinalizedBlock {
    number: u64,
    hash: String,
}

fn parse_block(value: &Value) -> Result<FinalizedBlock, AnyError> {
    Ok(FinalizedBlock {
        number: parse_quantity(value.get("number").ok_or("block number missing")?)?,
        hash: normalize_hash(
            value
                .get("hash")
                .and_then(Value::as_str)
                .ok_or("block hash missing")?,
            32,
        )?,
    })
}

async fn block_hash(client: &RpcClient, number: u64) -> Result<String, AnyError> {
    let value = client
        .call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )
        .await?;
    normalize_hash(
        value
            .get("hash")
            .and_then(Value::as_str)
            .ok_or("block hash missing")?,
        32,
    )
}

struct RpcClient {
    url: String,
    client: reqwest::Client,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

impl RpcClient {
    fn new(
        url: String,
        timeout: Duration,
        production: bool,
        max_response_bytes: usize,
    ) -> Result<Self, AnyError> {
        Ok(Self {
            url,
            client: reqwest::Client::builder()
                .https_only(production)
                .timeout(timeout)
                .build()?,
            next_id: AtomicU64::new(1),
            max_response_bytes,
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, AnyError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            }))
            .send()
            .await?
            .error_for_status()?;
        let payload = read_json_response(response, self.max_response_bytes).await?;
        if payload.get("id").and_then(Value::as_u64) != Some(id) {
            return Err("JSON-RPC response id mismatch".into());
        }
        if let Some(error) = payload.get("error") {
            return Err(format!("JSON-RPC {method} failed: {error}").into());
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| "JSON-RPC result missing".into())
    }
}

async fn read_json_response(response: reqwest::Response, limit: usize) -> Result<Value, AnyError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err("JSON-RPC response exceeds configured limit".into());
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
            return Err("JSON-RPC response exceeds configured limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

struct Settings {
    production: bool,
    rpc_url: String,
    contract_address: String,
    contract_code_hash: String,
    chain_id: u64,
    database: PathBuf,
    identities_file: PathBuf,
    issuer_keys_file: PathBuf,
    request_timeout: Duration,
    max_rpc_response_bytes: usize,
    poll_interval: Duration,
    fallback_confirmations: u64,
    once: bool,
    monitoring_bind: SocketAddr,
}

impl Settings {
    fn from_env() -> Result<Self, AnyError> {
        let production = parse_environment(&required("RI_ENVIRONMENT")?)?;
        let rpc_url = required("RI_WEB3_RPC_URL")?;
        if production && !rpc_url.starts_with("https://") {
            return Err("production RPC URL must use HTTPS".into());
        }
        let contract_address = normalize_hash(&required("RI_REGISTRY_CONTRACT_ADDRESS")?, 20)?;
        let contract_code_hash = normalize_hash(&required("RI_REGISTRY_CODE_HASH")?, 32)?;
        let chain_id = required("RI_WEB3_CHAIN_ID")?.parse()?;
        let request_timeout = Duration::from_millis(parse_u64("RI_RPC_TIMEOUT_MS", 5_000)?);
        let max_rpc_response_bytes =
            usize::try_from(parse_u64("RI_RPC_MAX_RESPONSE_BYTES", 4_194_304)?)?;
        let poll_interval =
            Duration::from_millis(parse_u64("RI_REGISTRY_POLL_INTERVAL_MS", 2_000)?);
        let fallback_confirmations = parse_u64("RI_REGISTRY_FALLBACK_CONFIRMATIONS", 12)?;
        if chain_id == 0 || request_timeout.is_zero() || poll_interval.is_zero() {
            return Err("Registry chain ID and time limits must be positive".into());
        }
        if max_rpc_response_bytes < 1_024 {
            return Err("RI_RPC_MAX_RESPONSE_BYTES must be at least 1024".into());
        }
        if production
            && (is_zero_hex(&contract_address)
                || is_zero_hex(&contract_code_hash)
                || fallback_confirmations == 0)
        {
            return Err(
                "production Registry pins and fallback confirmations must not be zero".into(),
            );
        }
        Ok(Self {
            production,
            rpc_url,
            contract_address,
            contract_code_hash,
            chain_id,
            database: required("RI_DATABASE")?.into(),
            identities_file: required("RI_IDENTITIES_FILE")?.into(),
            issuer_keys_file: required("RI_ISSUER_KEYS_FILE")?.into(),
            request_timeout,
            max_rpc_response_bytes,
            poll_interval,
            fallback_confirmations,
            once: env::var("RI_REGISTRY_SYNC_ONCE").is_ok_and(|value| value == "true"),
            monitoring_bind: env::var("RI_REGISTRY_MONITORING_BIND")
                .unwrap_or_else(|_| "127.0.0.1:9109".into())
                .parse()?,
        })
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

fn parse_quantity(value: &Value) -> Result<u64, AnyError> {
    let value = value.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(
        value.strip_prefix("0x").ok_or("quantity lacks 0x prefix")?,
        16,
    )?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AnyError> {
    Ok(hex::decode(
        value
            .strip_prefix("0x")
            .ok_or("hex value lacks 0x prefix")?,
    )?)
}

fn decode_bytes32(value: &str) -> Result<[u8; 32], AnyError> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| "value is not bytes32".into())
}

fn normalize_hash(value: &str, bytes: usize) -> Result<String, AnyError> {
    let normalized = value.to_ascii_lowercase();
    let raw = normalized
        .strip_prefix("0x")
        .ok_or("hex value lacks 0x prefix")?;
    if raw.len() != bytes * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("hex value must contain {bytes} bytes").into());
    }
    Ok(format!("0x{raw}"))
}

fn word_hex(output: &[u8], index: usize) -> String {
    format!("0x{}", hex::encode(&output[index * 32..(index + 1) * 32]))
}

fn word_u64(output: &[u8], index: usize) -> Result<u64, AnyError> {
    let word = &output[index * 32..(index + 1) * 32];
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI uint exceeds u64".into());
    }
    Ok(u64::from_be_bytes(word[24..].try_into()?))
}

fn status_name(value: u64) -> Result<&'static str, AnyError> {
    match value {
        0 => Ok("UNKNOWN"),
        1 => Ok("ACTIVE"),
        2 => Ok("SUSPENDED"),
        3 => Ok("REVOKED"),
        4 => Ok("EXPIRED"),
        _ => Err("unknown Registry status".into()),
    }
}

fn function_selector(function: &str) -> [u8; 4] {
    Keccak256::digest(function.as_bytes())[..4]
        .try_into()
        .expect("slice length is fixed")
}

fn required(name: &str) -> Result<String, AnyError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn parse_environment(value: &str) -> Result<bool, AnyError> {
    match value {
        "production" => Ok(true),
        "development" | "test" => Ok(false),
        _ => Err("RI_ENVIRONMENT must be production, development, or test".into()),
    }
}

fn is_zero_hex(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|raw| raw.bytes().all(|byte| byte == b'0'))
}

fn parse_u64(name: &str, default: u64) -> Result<u64, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::{function_selector, normalize_hash, status_name, word_u64};

    #[test]
    fn selectors_match_the_deployed_contract_abi() {
        assert_eq!(
            hex::encode(function_selector("getResolverAnchor(bytes32)")),
            "ddffffaf"
        );
        assert_eq!(
            hex::encode(function_selector("getRootStatus(bytes32)")),
            "f22858c9"
        );
        assert_eq!(
            hex::encode(function_selector("lookupResolverByEndpoint(bytes32)")),
            "b66499a6"
        );
    }

    #[test]
    fn abi_uint_and_status_decoding_is_bounded() {
        let mut word = [0_u8; 32];
        word[31] = 3;
        assert_eq!(word_u64(&word, 0).unwrap(), 3);
        assert_eq!(status_name(3).unwrap(), "REVOKED");
        word[0] = 1;
        assert!(word_u64(&word, 0).is_err());
    }

    #[test]
    fn address_and_hash_pins_require_exact_width() {
        assert!(normalize_hash("0x1111111111111111111111111111111111111111", 20).is_ok());
        assert!(normalize_hash("0x11", 20).is_err());
    }
}
