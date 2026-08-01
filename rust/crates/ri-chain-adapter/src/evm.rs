use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, RegistryAdapterMetadataV2, RegistryFinalityTypeV2,
    resolver_id_key,
};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

use crate::{
    AdapterResult, ChainSnapshot, ChainTarget, FinalizedCheckpoint, RegistryChainAdapter,
    RegistryRecord, ensure_crypto_provider, is_zero_hex, normalize_hash,
};

#[derive(Clone, Debug)]
pub struct EvmAdapterConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub runtime_code_hash: String,
    pub fallback_confirmations: u64,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub production: bool,
}

pub struct EvmRegistryAdapter {
    target: ChainTarget,
    contract_address: String,
    fallback_confirmations: u64,
    client: JsonRpcClient,
}

impl EvmRegistryAdapter {
    pub fn new(config: EvmAdapterConfig) -> AdapterResult<Self> {
        ensure_crypto_provider();
        let contract_address = normalize_hash(&config.contract_address, 20)?;
        let runtime_code_hash = normalize_hash(&config.runtime_code_hash, 32)?;
        if config.chain_id == 0
            || config.request_timeout.is_zero()
            || config.max_response_bytes < 1_024
        {
            return Err("EVM adapter limits and chain ID must be positive".into());
        }
        if config.production
            && (!config.rpc_url.starts_with("https://")
                || config.fallback_confirmations == 0
                || is_zero_hex(&contract_address)
                || is_zero_hex(&runtime_code_hash))
        {
            return Err("production EVM transport, pins, and confirmations are invalid".into());
        }
        let client = JsonRpcClient::new(
            config.rpc_url,
            config.request_timeout,
            config.production,
            config.max_response_bytes,
        )?;
        Ok(Self {
            target: ChainTarget {
                adapter: "evm".into(),
                chain_identity: format!("eip155:{}", config.chain_id),
                registry_locator: format!("evm:{contract_address}"),
                registry_schema_hash: runtime_code_hash.clone(),
                adapter_metadata: RegistryAdapterMetadataV2::Evm {
                    chain_id: config.chain_id,
                    contract_address: contract_address.clone(),
                    runtime_code_hash,
                },
            },
            contract_address,
            fallback_confirmations: config.fallback_confirmations,
            client,
        })
    }

    async fn finalized_checkpoint(&self) -> AdapterResult<FinalizedCheckpoint> {
        if let Ok(value) = self
            .client
            .call("eth_getBlockByNumber", json!(["finalized", false]))
            .await
            && !value.is_null()
        {
            return parse_block(&value, RegistryFinalityTypeV2::EvmFinalized);
        }
        let head = parse_quantity(&self.client.call("eth_blockNumber", json!([])).await?)?;
        let number = head
            .checked_sub(self.fallback_confirmations)
            .ok_or("chain head has fewer blocks than fallback confirmations")?;
        let value = self
            .client
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        parse_block(&value, RegistryFinalityTypeV2::EvmConfirmations)
    }

    async fn verify_target(&self, block_tag: &str) -> AdapterResult<()> {
        let chain_id = parse_quantity(&self.client.call("eth_chainId", json!([])).await?)?;
        let RegistryAdapterMetadataV2::Evm {
            chain_id: expected_chain_id,
            runtime_code_hash,
            ..
        } = &self.target.adapter_metadata
        else {
            return Err("EVM adapter target lacks typed EVM metadata".into());
        };
        if chain_id != *expected_chain_id {
            return Err(format!(
                "chain ID mismatch: expected {}, got {chain_id}",
                expected_chain_id
            )
            .into());
        }
        let code = self
            .client
            .call("eth_getCode", json!([self.contract_address, block_tag]))
            .await?
            .as_str()
            .ok_or("eth_getCode returned a non-string")?
            .to_owned();
        let code_bytes = decode_hex(&code)?;
        if code_bytes.is_empty() {
            return Err("Registry address has no runtime code".into());
        }
        let actual_code_hash = format!("0x{}", hex::encode(Keccak256::digest(code_bytes)));
        if actual_code_hash != *runtime_code_hash {
            return Err(format!(
                "Registry runtime code hash mismatch: expected {}, got {actual_code_hash}",
                runtime_code_hash
            )
            .into());
        }
        Ok(())
    }

    async fn resolver_record(
        &self,
        identity: &DnsServerIdentityV2,
        block_tag: &str,
    ) -> AdapterResult<RegistryRecord> {
        let expected_resolver_key = resolver_id_key(&identity.server_id);
        let anchor = get_resolver_anchor(
            &self.client,
            &self.contract_address,
            &expected_resolver_key,
            block_tag,
        )
        .await?;
        let root_status = get_status(
            &self.client,
            &self.contract_address,
            "getRootStatus(bytes32)",
            &anchor.state_root,
            block_tag,
        )
        .await?;
        let mut endpoint_owners = BTreeMap::new();
        for endpoint in &identity.endpoints {
            let endpoint_key = endpoint.registry_key()?;
            let bound_resolver = get_bytes32(
                &self.client,
                &self.contract_address,
                "lookupResolverByEndpoint(bytes32)",
                &endpoint_key,
                block_tag,
            )
            .await?;
            endpoint_owners.insert(endpoint_key, bound_resolver);
        }
        Ok(RegistryRecord {
            resolver_id_key: anchor.resolver_id_key,
            object_hash: anchor.object_hash,
            state_root: anchor.state_root,
            object_version: anchor.object_version,
            valid_until: anchor.valid_until,
            resolver_status: anchor.status,
            root_status,
            endpoint_owners,
        })
    }
}

#[async_trait]
impl RegistryChainAdapter for EvmRegistryAdapter {
    fn target(&self) -> &ChainTarget {
        &self.target
    }

    async fn read_snapshot(
        &self,
        identities: &[DnsServerIdentityV2],
        _issuer_keys: &IssuerKeyRegistry,
        _now: i64,
    ) -> AdapterResult<ChainSnapshot> {
        let checkpoint = self.finalized_checkpoint().await?;
        let block_tag = format!("0x{:x}", checkpoint.number);
        self.verify_target(&block_tag).await?;
        let mut records = BTreeMap::new();
        let mut resolver_keys = HashSet::new();
        for identity in identities {
            let record = self.resolver_record(identity, &block_tag).await?;
            if !resolver_keys.insert(record.resolver_id_key.clone()) {
                return Err("EVM Registry returned a duplicate Resolver ID key".into());
            }
            if records.insert(identity.server_id.clone(), record).is_some() {
                return Err("duplicate server_id requested from EVM adapter".into());
            }
        }
        let confirmed_hash = self.block_hash(checkpoint.number).await?;
        if confirmed_hash != checkpoint.hash {
            return Err("finalized block hash changed during EVM reconciliation".into());
        }
        let state_roots = records
            .values()
            .map(|record| record.state_root.as_str())
            .collect::<HashSet<_>>();
        if state_roots.len() != 1 {
            return Err("EVM Registry records do not share one state root".into());
        }
        let state_root = state_roots
            .into_iter()
            .next()
            .ok_or("EVM Registry snapshot has no state root")?
            .to_owned();
        Ok(ChainSnapshot {
            generation: checkpoint.number,
            checkpoint,
            state_root,
            records,
        })
    }

    async fn block_hash(&self, number: u64) -> AdapterResult<String> {
        let value = self
            .client
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

fn parse_block(
    value: &Value,
    finality_type: RegistryFinalityTypeV2,
) -> AdapterResult<FinalizedCheckpoint> {
    Ok(FinalizedCheckpoint {
        number: parse_quantity(value.get("number").ok_or("block number missing")?)?,
        hash: normalize_hash(
            value
                .get("hash")
                .and_then(Value::as_str)
                .ok_or("block hash missing")?,
            32,
        )?,
        finality_type,
    })
}

async fn get_resolver_anchor(
    client: &JsonRpcClient,
    contract: &str,
    resolver_key: &str,
    block_tag: &str,
) -> AdapterResult<ResolverAnchor> {
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
    client: &JsonRpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> AdapterResult<String> {
    let output = eth_call(client, contract, function, argument, block_tag).await?;
    if output.len() != 32 {
        return Err("status call returned an invalid ABI payload".into());
    }
    Ok(status_name(word_u64(&output, 0)?)?.into())
}

async fn get_bytes32(
    client: &JsonRpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> AdapterResult<String> {
    let output = eth_call(client, contract, function, argument, block_tag).await?;
    if output.len() != 32 {
        return Err("bytes32 call returned an invalid ABI payload".into());
    }
    Ok(word_hex(&output, 0))
}

async fn eth_call(
    client: &JsonRpcClient,
    contract: &str,
    function: &str,
    argument: &str,
    block_tag: &str,
) -> AdapterResult<Vec<u8>> {
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

struct JsonRpcClient {
    url: String,
    client: reqwest::Client,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

impl JsonRpcClient {
    fn new(
        url: String,
        timeout: Duration,
        production: bool,
        max_response_bytes: usize,
    ) -> AdapterResult<Self> {
        Ok(Self {
            url,
            client: reqwest::Client::builder()
                .no_proxy()
                .https_only(production)
                .timeout(timeout)
                .build()?,
            next_id: AtomicU64::new(1),
            max_response_bytes,
        })
    }

    async fn call(&self, method: &str, params: Value) -> AdapterResult<Value> {
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

async fn read_json_response(response: reqwest::Response, limit: usize) -> AdapterResult<Value> {
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

fn parse_quantity(value: &Value) -> AdapterResult<u64> {
    let value = value.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(
        value.strip_prefix("0x").ok_or("quantity lacks 0x prefix")?,
        16,
    )?)
}

fn decode_hex(value: &str) -> AdapterResult<Vec<u8>> {
    Ok(hex::decode(
        value
            .strip_prefix("0x")
            .ok_or("hex value lacks 0x prefix")?,
    )?)
}

fn decode_bytes32(value: &str) -> AdapterResult<[u8; 32]> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| "value is not bytes32".into())
}

fn word_hex(output: &[u8], index: usize) -> String {
    format!("0x{}", hex::encode(&output[index * 32..(index + 1) * 32]))
}

fn word_u64(output: &[u8], index: usize) -> AdapterResult<u64> {
    let word = &output[index * 32..(index + 1) * 32];
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI uint exceeds u64".into());
    }
    Ok(u64::from_be_bytes(word[24..].try_into()?))
}

fn status_name(value: u64) -> AdapterResult<&'static str> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use ri_core::{DnsServerIdentityV2, DnsServerRole, IssuerKeyRegistry, RegistryFinalityTypeV2};
    use serde_json::{Value, json};
    use sha3::{Digest, Keccak256};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{EvmAdapterConfig, EvmRegistryAdapter, function_selector, status_name, word_u64};
    use crate::RegistryChainAdapter;

    const BLOCK_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BLOCK_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Clone)]
    struct RpcState {
        chain_id: u64,
        code: String,
        finalized_available: bool,
        fork_after_finalized: bool,
        wrong_id: bool,
        eth_call_error: bool,
        oversized: bool,
    }

    async fn rpc(State(state): State<Arc<RpcState>>, Json(request): Json<Value>) -> Json<Value> {
        let id = request["id"].as_u64().unwrap();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!(format!("0x{:x}", state.chain_id)),
            "eth_blockNumber" => json!("0x20"),
            "eth_getCode" => json!(state.code),
            "eth_getBlockByNumber" => {
                let tag = request["params"][0].as_str().unwrap();
                if tag == "finalized" && !state.finalized_available {
                    Value::Null
                } else {
                    json!({
                        "number": if tag == "finalized" { "0x14" } else { tag },
                        "hash": if tag != "finalized" && state.fork_after_finalized {
                            BLOCK_B
                        } else {
                            BLOCK_A
                        }
                    })
                }
            }
            "eth_call" if state.eth_call_error => {
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32000, "message": "state unavailable"}
                }));
            }
            "eth_call" => json!("0x"),
            _ => Value::Null,
        };
        let mut response = json!({
            "jsonrpc": "2.0",
            "id": if state.wrong_id { id + 1 } else { id },
            "result": result
        });
        if state.oversized {
            response["padding"] = json!("x".repeat(2_048));
        }
        Json(response)
    }

    async fn spawn_rpc(state: RpcState) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", post(rpc))
                    .with_state(Arc::new(state)),
            )
            .await
            .unwrap();
        });
        (format!("http://{address}"), task)
    }

    fn state() -> RpcState {
        RpcState {
            chain_id: 31_337,
            code: "0x6000".into(),
            finalized_available: true,
            fork_after_finalized: false,
            wrong_id: false,
            eth_call_error: false,
            oversized: false,
        }
    }

    fn config(url: String, code_hash: String) -> EvmAdapterConfig {
        EvmAdapterConfig {
            rpc_url: url,
            chain_id: 31_337,
            contract_address: "0x1111111111111111111111111111111111111111".into(),
            runtime_code_hash: code_hash,
            fallback_confirmations: 12,
            request_timeout: Duration::from_secs(1),
            max_response_bytes: 1_024,
            production: false,
        }
    }

    fn code_hash() -> String {
        format!("0x{}", hex::encode(Keccak256::digest([0x60, 0x00])))
    }

    fn identity() -> DnsServerIdentityV2 {
        DnsServerIdentityV2 {
            schema_version: "dns-server-identity-v2".into(),
            server_id: "operator/r1".into(),
            operator_id: "operator".into(),
            role: DnsServerRole::Recursive,
            endpoints: Vec::new(),
            anycast: false,
            anycast_service_id: None,
            agent: None,
            valid_from: 1,
            valid_until: 2_000,
            object_version: 1,
            status: "ACTIVE".into(),
            issuer: "issuer".into(),
            key_id: "key".into(),
            signature: None,
        }
    }

    #[test]
    fn selectors_match_registry_abi() {
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
    fn abi_integer_is_bounded() {
        let mut word = [0_u8; 32];
        word[31] = 3;
        assert_eq!(word_u64(&word, 0).unwrap(), 3);
        assert_eq!(status_name(3).unwrap(), "REVOKED");
        word[0] = 1;
        assert!(word_u64(&word, 0).is_err());
    }

    #[tokio::test]
    async fn chain_code_and_runtime_hash_pins_fail_closed() {
        let mut cases = Vec::new();
        let mut mismatch_chain = state();
        mismatch_chain.chain_id = 1;
        cases.push(mismatch_chain);
        let mut no_code = state();
        no_code.code = "0x".into();
        cases.push(no_code);
        let hash_mismatch = state();
        cases.push(hash_mismatch);

        for (index, state) in cases.into_iter().enumerate() {
            let (url, task) = spawn_rpc(state).await;
            let expected_hash = if index == 2 {
                format!("0x{}", "11".repeat(32))
            } else {
                code_hash()
            };
            let adapter = EvmRegistryAdapter::new(config(url, expected_hash)).unwrap();
            assert!(
                adapter
                    .read_snapshot(&[], &IssuerKeyRegistry::default(), 1_000)
                    .await
                    .is_err()
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn finalized_fallback_uses_configured_confirmations() {
        let mut rpc_state = state();
        rpc_state.finalized_available = false;
        let (url, task) = spawn_rpc(rpc_state).await;
        let adapter = EvmRegistryAdapter::new(config(url, code_hash())).unwrap();
        let checkpoint = adapter.finalized_checkpoint().await.unwrap();
        assert_eq!(checkpoint.number, 20);
        assert_eq!(
            checkpoint.finality_type,
            RegistryFinalityTypeV2::EvmConfirmations
        );
        task.abort();
    }

    #[tokio::test]
    async fn specified_block_read_and_checkpoint_change_fail_closed() {
        let mut unavailable = state();
        unavailable.eth_call_error = true;
        let (url, task) = spawn_rpc(unavailable).await;
        let adapter = EvmRegistryAdapter::new(config(url, code_hash())).unwrap();
        assert!(
            adapter
                .read_snapshot(&[identity()], &IssuerKeyRegistry::default(), 1_000)
                .await
                .is_err()
        );
        task.abort();

        let mut forked = state();
        forked.fork_after_finalized = true;
        let (url, task) = spawn_rpc(forked).await;
        let adapter = EvmRegistryAdapter::new(config(url, code_hash())).unwrap();
        assert!(
            adapter
                .read_snapshot(&[], &IssuerKeyRegistry::default(), 1_000)
                .await
                .is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn rpc_id_and_response_size_limits_fail_closed() {
        for rpc_state in [
            RpcState {
                wrong_id: true,
                ..state()
            },
            RpcState {
                oversized: true,
                ..state()
            },
        ] {
            let (url, task) = spawn_rpc(rpc_state).await;
            let adapter = EvmRegistryAdapter::new(config(url, code_hash())).unwrap();
            assert!(adapter.finalized_checkpoint().await.is_err());
            task.abort();
        }
    }
}
