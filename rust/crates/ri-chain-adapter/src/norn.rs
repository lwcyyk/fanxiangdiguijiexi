use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use prost::Message;
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, RegistryAdapterMetadataV2, RegistryFinalityTypeV2,
    resolver_id_key, sha256_hex, verify_ed25519,
};
use serde::{Deserialize, Serialize};
use tonic::codec::ProstCodec;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, client::Grpc};
use url::Url;

use crate::{
    AdapterResult, ChainSnapshot, ChainTarget, FinalizedCheckpoint, RegistryChainAdapter,
    RegistryRecord, ensure_crypto_provider, is_zero_hex, normalize_hash,
};

pub const NORN_REGISTRY_SNAPSHOT_V1: &str = "resolver-identity-norn-registry-snapshot-v1";
const MAX_SNAPSHOT_ENTRIES: usize = 10_000;
const MAX_ENDPOINTS_PER_ENTRY: usize = 32;
const MAX_TEXT_FIELD_BYTES: usize = 256;
const NORN_SCHEMA_DESCRIPTOR_V1: &str = concat!(
    "resolver-identity-norn-registry-snapshot-v1:",
    "chain_id,genesis_block_hash,registry_address,registry_key,",
    "registry_schema_hash,snapshot_version,checkpoint_height,checkpoint_hash,",
    "state_root,root_status,published_at,valid_until,issuer,key_id,",
    "entries[server_id,resolver_id_key,object_hash,object_version,valid_until,",
    "status,endpoint_keys],signature"
);

pub fn norn_registry_schema_hash() -> String {
    sha256_hex(NORN_SCHEMA_DESCRIPTOR_V1)
}

/// Explicitly scoped client for local/preproduction Norn administration.
///
/// Go-Norn's write RPC signs with the node consensus key. Runtime Registry
/// Sync never constructs this client and only uses the read-only client below.
pub struct NornDevelopmentClient {
    client: NornRpcClient,
}

impl NornDevelopmentClient {
    pub fn new(url: String, timeout: Duration, max_response_bytes: usize) -> AdapterResult<Self> {
        ensure_crypto_provider();
        Ok(Self {
            client: NornRpcClient::new(url, timeout, max_response_bytes, None, false)?,
        })
    }

    pub fn new_with_tls(
        url: String,
        timeout: Duration,
        max_response_bytes: usize,
        tls: NornClientTlsMaterial,
    ) -> AdapterResult<Self> {
        ensure_crypto_provider();
        Ok(Self {
            client: NornRpcClient::new(url, timeout, max_response_bytes, Some(&tls), false)?,
        })
    }

    pub async fn head(&self) -> AdapterResult<u64> {
        self.client.head().await
    }

    pub async fn block(&self, number: u64) -> AdapterResult<FinalizedCheckpoint> {
        self.client.block(number).await
    }

    pub async fn transactions(
        &self,
        number: u64,
    ) -> AdapterResult<Vec<NornDevelopmentTransaction>> {
        Ok(self
            .client
            .full_block(number)
            .await?
            .transactions
            .into_iter()
            .map(|transaction| NornDevelopmentTransaction {
                hash: transaction.hash,
                receiver: transaction.receiver,
                data: transaction.data,
            })
            .collect())
    }

    pub async fn read(&self, address: &str, key: &str) -> AdapterResult<String> {
        let address = normalize_hash(address, 20)?;
        self.client.read_contract_address(&address, key).await
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NornDevelopmentTransaction {
    pub hash: Option<String>,
    pub receiver: Option<String>,
    pub data: Option<String>,
}

#[derive(Clone)]
pub struct NornAdapterConfig {
    pub rpc_urls: Vec<String>,
    /// Locally governed non-zero namespace used by V2 consumers. Chain
    /// authenticity is pinned by `genesis_block_hash`.
    pub chain_id: u64,
    pub genesis_block_hash: String,
    pub registry_address: String,
    pub registry_key: String,
    pub registry_schema_hash: String,
    pub snapshot_signer_issuer: String,
    pub snapshot_signer_key_id: String,
    pub confirmations: u64,
    pub registry_start_height: u64,
    pub max_scan_blocks: u64,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub tls: Option<NornClientTlsMaterial>,
    pub production: bool,
}

#[derive(Clone)]
pub struct NornClientTlsMaterial {
    pub ca_certificate_pem: Vec<u8>,
    pub client_certificate_pem: Vec<u8>,
    pub client_private_key_pem: Vec<u8>,
}

pub struct NornRegistryAdapter {
    target: ChainTarget,
    genesis_block_hash: String,
    registry_address: String,
    registry_key: String,
    chain_id: u64,
    snapshot_signer_issuer: String,
    snapshot_signer_key_id: String,
    confirmations: u64,
    registry_start_height: u64,
    max_scan_blocks: u64,
    clients: Vec<NornRpcClient>,
}

impl NornRegistryAdapter {
    pub fn new(config: NornAdapterConfig) -> AdapterResult<Self> {
        ensure_crypto_provider();
        let genesis_block_hash = normalize_hash(&config.genesis_block_hash, 32)?;
        let registry_address = normalize_hash(&config.registry_address, 20)?;
        let registry_schema_hash = normalize_hash(&config.registry_schema_hash, 32)?;
        if config.chain_id == 0
            || config.confirmations == 0
            || config.max_scan_blocks == 0
            || config.request_timeout.is_zero()
            || config.max_response_bytes < 1_024
            || config.registry_key.is_empty()
            || config.registry_key.len() > 256
            || config.snapshot_signer_issuer.is_empty()
            || config.snapshot_signer_key_id.is_empty()
        {
            return Err("Norn adapter pins and limits are invalid".into());
        }
        if registry_schema_hash != norn_registry_schema_hash() {
            return Err(format!(
                "Norn Registry schema hash mismatch: expected {}",
                norn_registry_schema_hash()
            )
            .into());
        }
        if is_zero_hex(&genesis_block_hash) || is_zero_hex(&registry_address) {
            return Err("Norn genesis hash and Registry address must not be zero".into());
        }
        let unique_urls = config.rpc_urls.iter().collect::<HashSet<_>>();
        if unique_urls.len() != config.rpc_urls.len() || config.rpc_urls.len() < 2 {
            return Err("Norn Registry reads require two unique RPC URLs".into());
        }
        let rpc_hosts = config
            .rpc_urls
            .iter()
            .map(|endpoint| {
                Url::parse(endpoint).ok().and_then(|url| {
                    Some((url.host_str()?.to_owned(), url.port_or_known_default()?))
                })
            })
            .collect::<Option<HashSet<_>>>()
            .ok_or("Norn RPC endpoint URL is invalid")?;
        if rpc_hosts.len() != config.rpc_urls.len() {
            return Err("Norn RPC endpoints must use independent network origins".into());
        }
        if config.production
            && (config
                .rpc_urls
                .iter()
                .any(|url| !url.starts_with("https://")))
        {
            return Err(
                "production Norn requires at least two independent HTTPS gRPC endpoints".into(),
            );
        }
        let clients = config
            .rpc_urls
            .into_iter()
            .map(|url| {
                NornRpcClient::new(
                    url,
                    config.request_timeout,
                    config.max_response_bytes,
                    config.tls.as_ref(),
                    config.production,
                )
            })
            .collect::<AdapterResult<Vec<_>>>()?;
        Ok(Self {
            target: ChainTarget {
                adapter: "norn".into(),
                chain_identity: format!("norn-genesis:{genesis_block_hash}"),
                registry_locator: format!("norn:{registry_address}#{}", config.registry_key),
                registry_schema_hash: registry_schema_hash.clone(),
                adapter_metadata: RegistryAdapterMetadataV2::Norn {
                    genesis_block_hash: genesis_block_hash.clone(),
                    registry_address: registry_address.clone(),
                    registry_key: config.registry_key.clone(),
                    snapshot_signer_issuer: config.snapshot_signer_issuer.clone(),
                    snapshot_signer_key_id: config.snapshot_signer_key_id.clone(),
                },
            },
            genesis_block_hash,
            registry_address,
            registry_key: config.registry_key,
            chain_id: config.chain_id,
            snapshot_signer_issuer: config.snapshot_signer_issuer,
            snapshot_signer_key_id: config.snapshot_signer_key_id,
            confirmations: config.confirmations,
            registry_start_height: config.registry_start_height,
            max_scan_blocks: config.max_scan_blocks,
            clients,
        })
    }

    async fn agreed_block(&self, number: u64) -> AdapterResult<FinalizedCheckpoint> {
        let mut blocks = Vec::with_capacity(self.clients.len());
        for client in &self.clients {
            blocks.push(client.block(number).await?);
        }
        require_agreement(blocks, &format!("Norn RPC disagreement at block {number}"))
    }

    async fn finalized_checkpoint(&self) -> AdapterResult<FinalizedCheckpoint> {
        let mut heads = Vec::with_capacity(self.clients.len());
        for client in &self.clients {
            heads.push(client.head().await?);
        }
        let number = confirmation_derived_height(&heads, self.confirmations)?;
        self.agreed_block(number).await
    }

    async fn agreed_registry_value(&self) -> AdapterResult<String> {
        let mut values = Vec::with_capacity(self.clients.len());
        for client in &self.clients {
            let value = client
                .read_contract_address(&self.registry_address, &self.registry_key)
                .await?;
            if value.is_empty() {
                return Err("Norn Registry state is empty".into());
            }
            values.push(value);
        }
        require_agreement(
            values,
            "Norn RPC nodes returned different Registry snapshots",
        )
    }

    async fn verify_finalized_inclusion(
        &self,
        expected_value: &str,
        finalized_height: u64,
    ) -> AdapterResult<()> {
        let lower_bound = finalized_height
            .saturating_sub(self.max_scan_blocks.saturating_sub(1))
            .max(self.registry_start_height);
        for height in (lower_bound..=finalized_height).rev() {
            let block = self.agreed_full_block(height).await?;
            if let Some(command) = registry_command(
                &block.transactions,
                &self.registry_address,
                &self.registry_key,
            ) {
                if command.operation != "set" {
                    return Err("latest finalized Norn Registry command is not set".into());
                }
                if command.value != expected_value {
                    return Err(
                        "current Norn Registry value is not the latest finalized value".into(),
                    );
                }
                return Ok(());
            }
        }
        Err(format!(
            "Norn Registry publication was not found in finalized blocks {lower_bound}..={finalized_height}"
        )
        .into())
    }

    async fn agreed_full_block(&self, number: u64) -> AdapterResult<Block> {
        let mut blocks = Vec::with_capacity(self.clients.len());
        for client in &self.clients {
            blocks.push(client.full_block(number).await?);
        }
        require_agreement(
            blocks,
            &format!("Norn RPC full-block disagreement at height {number}"),
        )
    }

    async fn validate_snapshot(
        &self,
        snapshot: &NornRegistrySnapshotV1,
        issuer_keys: &IssuerKeyRegistry,
        accepted_checkpoint: &FinalizedCheckpoint,
        now: i64,
    ) -> AdapterResult<BTreeMap<String, RegistryRecord>> {
        validate_snapshot_shape(
            snapshot,
            issuer_keys,
            &SnapshotPins {
                chain_id: self.chain_id,
                genesis_block_hash: &self.genesis_block_hash,
                registry_address: &self.registry_address,
                registry_key: &self.registry_key,
                registry_schema_hash: &self.target.registry_schema_hash,
                signer_issuer: &self.snapshot_signer_issuer,
                signer_key_id: &self.snapshot_signer_key_id,
                accepted_checkpoint,
                now,
            },
        )?;
        let signed_checkpoint = self.agreed_block(snapshot.checkpoint_height).await?;
        if signed_checkpoint.hash != snapshot.checkpoint_hash {
            return Err("Norn snapshot checkpoint hash is not canonical".into());
        }
        snapshot_records(snapshot)
    }
}

fn require_agreement<T: PartialEq>(values: Vec<T>, disagreement: &str) -> AdapterResult<T> {
    let mut values = values.into_iter();
    let accepted = values
        .next()
        .ok_or("Norn adapter has no independent RPC results")?;
    if values.any(|value| value != accepted) {
        return Err(disagreement.to_owned().into());
    }
    Ok(accepted)
}

fn confirmation_derived_height(heads: &[u64], confirmations: u64) -> AdapterResult<u64> {
    let minimum_head = heads
        .iter()
        .copied()
        .min()
        .ok_or("Norn adapter has no RPC heads")?;
    let number = minimum_head
        .checked_sub(confirmations)
        .ok_or("Norn head has fewer blocks than configured confirmations")?;
    if number == 0 {
        return Err("Norn finalized checkpoint has not advanced past genesis".into());
    }
    Ok(number)
}

#[async_trait]
impl RegistryChainAdapter for NornRegistryAdapter {
    fn target(&self) -> &ChainTarget {
        &self.target
    }

    async fn read_snapshot(
        &self,
        _identities: &[DnsServerIdentityV2],
        issuer_keys: &IssuerKeyRegistry,
        now: i64,
    ) -> AdapterResult<ChainSnapshot> {
        let genesis = self.agreed_block(0).await?;
        if genesis.hash != self.genesis_block_hash {
            return Err(format!(
                "Norn genesis mismatch: expected {}, got {}",
                self.genesis_block_hash, genesis.hash
            )
            .into());
        }
        let checkpoint = self.finalized_checkpoint().await?;
        let value = self.agreed_registry_value().await?;
        if value.len() > self.clients[0].max_response_bytes {
            return Err("Norn Registry snapshot exceeds configured response limit".into());
        }
        self.verify_finalized_inclusion(&value, checkpoint.number)
            .await?;
        let snapshot: NornRegistrySnapshotV1 = serde_json::from_str(&value)?;
        let records = self
            .validate_snapshot(&snapshot, issuer_keys, &checkpoint, now)
            .await?;
        let confirmed_hash = self.block_hash(checkpoint.number).await?;
        if confirmed_hash != checkpoint.hash {
            return Err("Norn checkpoint hash changed during reconciliation".into());
        }
        Ok(ChainSnapshot {
            checkpoint,
            state_root: normalize_hash(&snapshot.state_root, 32)?,
            generation: snapshot.snapshot_version,
            records,
        })
    }

    async fn block_hash(&self, number: u64) -> AdapterResult<String> {
        Ok(self.agreed_block(number).await?.hash)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NornRegistrySnapshotV1 {
    pub schema_version: String,
    pub chain_id: u64,
    pub genesis_block_hash: String,
    pub registry_address: String,
    pub registry_key: String,
    pub registry_schema_hash: String,
    pub snapshot_version: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub state_root: String,
    pub root_status: String,
    pub published_at: i64,
    pub valid_until: i64,
    pub issuer: String,
    pub key_id: String,
    pub entries: Vec<NornRegistrySnapshotEntryV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NornRegistrySnapshotEntryV1 {
    pub server_id: String,
    pub resolver_id_key: String,
    pub object_hash: String,
    pub object_version: u64,
    pub valid_until: i64,
    pub status: String,
    pub endpoint_keys: Vec<String>,
}

struct SnapshotPins<'a> {
    chain_id: u64,
    genesis_block_hash: &'a str,
    registry_address: &'a str,
    registry_key: &'a str,
    registry_schema_hash: &'a str,
    signer_issuer: &'a str,
    signer_key_id: &'a str,
    accepted_checkpoint: &'a FinalizedCheckpoint,
    now: i64,
}

fn validate_snapshot_shape(
    snapshot: &NornRegistrySnapshotV1,
    issuer_keys: &IssuerKeyRegistry,
    pins: &SnapshotPins<'_>,
) -> AdapterResult<()> {
    if snapshot.schema_version != NORN_REGISTRY_SNAPSHOT_V1
        || snapshot.chain_id != pins.chain_id
        || normalize_hash(&snapshot.genesis_block_hash, 32)? != pins.genesis_block_hash
        || normalize_hash(&snapshot.registry_address, 20)? != pins.registry_address
        || snapshot.registry_key != pins.registry_key
        || normalize_hash(&snapshot.registry_schema_hash, 32)? != pins.registry_schema_hash
        || snapshot.snapshot_version == 0
        || snapshot.checkpoint_height == 0
        || snapshot.checkpoint_height > pins.accepted_checkpoint.number
        || snapshot.root_status != "ACTIVE"
        || snapshot.published_at <= 0
        || snapshot.published_at > pins.now
        || snapshot.valid_until < pins.now
        || snapshot.valid_until <= snapshot.published_at
        || snapshot.issuer != pins.signer_issuer
        || snapshot.key_id != pins.signer_key_id
        || snapshot.entries.is_empty()
        || snapshot.entries.len() > MAX_SNAPSHOT_ENTRIES
    {
        return Err("Norn Registry snapshot pins or validity window are invalid".into());
    }
    normalize_hash(&snapshot.checkpoint_hash, 32)?;
    normalize_hash(&snapshot.state_root, 32)?;
    let public_key = issuer_keys
        .get(&snapshot.issuer, &snapshot.key_id)
        .ok_or("Norn snapshot issuer key is not trusted")?;
    verify_ed25519(snapshot, public_key)?;
    Ok(())
}

fn snapshot_records(
    snapshot: &NornRegistrySnapshotV1,
) -> AdapterResult<BTreeMap<String, RegistryRecord>> {
    let state_root = normalize_hash(&snapshot.state_root, 32)?;
    let calculated_root = norn_state_root(&snapshot.entries)?;
    if calculated_root != state_root {
        return Err(format!(
            "Norn snapshot state root mismatch: expected {state_root}, got {calculated_root}"
        )
        .into());
    }
    let mut records = BTreeMap::new();
    let mut resolver_keys = HashSet::new();
    let mut all_endpoints = HashSet::new();
    for entry in &snapshot.entries {
        let resolver_key = normalize_hash(&entry.resolver_id_key, 32)?;
        if entry.server_id.is_empty()
            || entry.server_id.len() > MAX_TEXT_FIELD_BYTES
            || entry.object_version == 0
            || entry.valid_until <= 0
            || entry.status.is_empty()
            || entry.status.len() > 32
            || entry.endpoint_keys.is_empty()
            || entry.endpoint_keys.len() > MAX_ENDPOINTS_PER_ENTRY
            || resolver_key != resolver_id_key(&entry.server_id)
            || !resolver_keys.insert(resolver_key.clone())
        {
            return Err(format!("invalid Norn snapshot entry {}", entry.server_id).into());
        }
        let mut endpoint_owners = BTreeMap::new();
        for endpoint in &entry.endpoint_keys {
            let endpoint = normalize_hash(endpoint, 32)?;
            if !all_endpoints.insert(endpoint.clone()) {
                return Err(format!("duplicate Norn Registry endpoint {endpoint}").into());
            }
            endpoint_owners.insert(endpoint, resolver_key.clone());
        }
        let record = RegistryRecord {
            resolver_id_key: resolver_key,
            object_hash: normalize_hash(&entry.object_hash, 32)?,
            state_root: state_root.clone(),
            object_version: entry.object_version,
            valid_until: entry.valid_until,
            resolver_status: entry.status.clone(),
            root_status: snapshot.root_status.clone(),
            endpoint_owners,
        };
        if records.insert(entry.server_id.clone(), record).is_some() {
            return Err(format!("duplicate Norn server_id {}", entry.server_id).into());
        }
    }
    Ok(records)
}

fn norn_state_root(entries: &[NornRegistrySnapshotEntryV1]) -> AdapterResult<String> {
    let mut previous_server_id: Option<&str> = None;
    let mut level = Vec::with_capacity(entries.len());
    for entry in entries {
        if previous_server_id.is_some_and(|previous| previous >= entry.server_id.as_str()) {
            return Err("Norn snapshot entries must be sorted by unique server_id".into());
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

struct NornRpcClient {
    channel: Channel,
    max_response_bytes: usize,
}

impl NornRpcClient {
    fn new(
        url: String,
        timeout: Duration,
        max_response_bytes: usize,
        tls: Option<&NornClientTlsMaterial>,
        production: bool,
    ) -> AdapterResult<Self> {
        let mut endpoint = Endpoint::from_shared(url.clone())?
            .timeout(timeout)
            .connect_timeout(timeout);
        if url.starts_with("https://") {
            let mut tls_config = ClientTlsConfig::new().with_webpki_roots();
            if let Some(material) = tls {
                if material.ca_certificate_pem.is_empty()
                    || material.client_certificate_pem.is_empty()
                    || material.client_private_key_pem.is_empty()
                {
                    return Err("Norn mTLS material is incomplete".into());
                }
                tls_config = tls_config
                    .ca_certificate(Certificate::from_pem(material.ca_certificate_pem.clone()))
                    .identity(Identity::from_pem(
                        material.client_certificate_pem.clone(),
                        material.client_private_key_pem.clone(),
                    ));
            } else if production {
                return Err("production Norn requires mTLS client material".into());
            }
            endpoint = endpoint.tls_config(tls_config)?;
        } else if production {
            return Err("production Norn RPC must use HTTPS".into());
        }
        Ok(Self {
            channel: endpoint.connect_lazy(),
            max_response_bytes,
        })
    }

    async fn head(&self) -> AdapterResult<u64> {
        let response: BlockNumberResp = self
            .unary(
                Empty {},
                PathAndQuery::from_static("/Blockchain/GetBlockNumber"),
            )
            .await?;
        response
            .number
            .ok_or_else(|| "Norn block number missing".into())
    }

    async fn block(&self, number: u64) -> AdapterResult<FinalizedCheckpoint> {
        let block = self.block_response(number, false).await?;
        let header = block.header.ok_or("Norn block header missing")?;
        let actual_number = header.height.ok_or("Norn block height missing")?;
        if actual_number != number {
            return Err(format!(
                "Norn block height mismatch: requested {number}, got {actual_number}"
            )
            .into());
        }
        Ok(FinalizedCheckpoint {
            number,
            hash: normalize_hash(
                header
                    .block_hash
                    .as_deref()
                    .ok_or("Norn block hash missing")?,
                32,
            )?,
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        })
    }

    async fn full_block(&self, number: u64) -> AdapterResult<Block> {
        let block = self.block_response(number, true).await?;
        let header = block.header.as_ref().ok_or("Norn block header missing")?;
        if header.height != Some(number) {
            return Err(format!("Norn full block height mismatch at {number}").into());
        }
        normalize_hash(
            header
                .block_hash
                .as_deref()
                .ok_or("Norn block hash missing")?,
            32,
        )?;
        Ok(block)
    }

    async fn block_response(&self, number: u64, full: bool) -> AdapterResult<Block> {
        let response: GetBlockResp = self
            .unary(
                GetBlockReq {
                    number: Some(number),
                    hash: None,
                    full: Some(full),
                },
                PathAndQuery::from_static("/Blockchain/GetBlockByNumber"),
            )
            .await?;
        response
            .body
            .ok_or_else(|| "Norn block body missing".into())
    }

    async fn read_contract_address(&self, address: &str, key: &str) -> AdapterResult<String> {
        let response: ReadContractAddressResp = self
            .unary(
                ReadContractAddressReq {
                    address: Some(address.trim_start_matches("0x").into()),
                    key: Some(key.into()),
                },
                PathAndQuery::from_static("/Blockchain/ReadContractAddress"),
            )
            .await?;
        response
            .hex
            .ok_or_else(|| "Norn Registry value missing".into())
    }

    async fn unary<Req, Resp>(&self, request: Req, path: PathAndQuery) -> AdapterResult<Resp>
    where
        Req: Message + Default + 'static,
        Resp: Message + Default + 'static,
    {
        let mut grpc =
            Grpc::new(self.channel.clone()).max_decoding_message_size(self.max_response_bytes);
        grpc.ready()
            .await
            .map_err(|error| format!("Norn gRPC service unavailable: {error}"))?;
        let response = grpc
            .unary(Request::new(request), path, ProstCodec::default())
            .await?;
        Ok(response.into_inner())
    }
}

#[derive(Clone, PartialEq, Message)]
struct Empty {}

#[derive(Clone, PartialEq, Message)]
struct BlockNumberResp {
    #[prost(uint64, optional, tag = "2")]
    number: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct GetBlockReq {
    #[prost(uint64, optional, tag = "1")]
    number: Option<u64>,
    #[prost(string, optional, tag = "2")]
    hash: Option<String>,
    #[prost(bool, optional, tag = "3")]
    full: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct GetBlockResp {
    #[prost(message, optional, tag = "2")]
    body: Option<Block>,
}

#[derive(Clone, PartialEq, Message)]
struct Block {
    #[prost(message, optional, tag = "1")]
    header: Option<BlockHeader>,
    #[prost(message, repeated, tag = "2")]
    transactions: Vec<Transaction>,
}

#[derive(Clone, PartialEq, Message)]
struct BlockHeader {
    #[prost(string, optional, tag = "3")]
    block_hash: Option<String>,
    #[prost(uint64, optional, tag = "5")]
    height: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct Transaction {
    #[prost(string, optional, tag = "1")]
    hash: Option<String>,
    #[prost(string, optional, tag = "3")]
    receiver: Option<String>,
    #[prost(string, optional, tag = "9")]
    data: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ReadContractAddressReq {
    #[prost(string, optional, tag = "1")]
    address: Option<String>,
    #[prost(string, optional, tag = "2")]
    key: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ReadContractAddressResp {
    #[prost(string, optional, tag = "1")]
    hex: Option<String>,
}

struct DataCommand {
    operation: String,
    key: String,
    value: String,
}

fn decode_data_command(encoded: &str) -> AdapterResult<DataCommand> {
    let bytes = hex::decode(
        encoded
            .strip_prefix("0x")
            .ok_or("Norn transaction data lacks 0x prefix")?,
    )?;
    if bytes.len() < 40 {
        return Err("Norn DataCommand is shorter than its Karmem header".into());
    }
    let field = |offset: usize| -> AdapterResult<&[u8]> {
        let data_offset =
            usize::try_from(u32::from_le_bytes(bytes[offset..offset + 4].try_into()?))?;
        let size = usize::try_from(u32::from_le_bytes(
            bytes[offset + 4..offset + 8].try_into()?,
        ))?;
        let end = data_offset
            .checked_add(size)
            .ok_or("Norn DataCommand field length overflow")?;
        bytes
            .get(data_offset..end)
            .ok_or_else(|| "Norn DataCommand field is out of bounds".into())
    };
    Ok(DataCommand {
        operation: String::from_utf8(field(4)?.to_vec())?,
        key: String::from_utf8(field(16)?.to_vec())?,
        value: String::from_utf8(field(28)?.to_vec())?,
    })
}

fn registry_command(
    transactions: &[Transaction],
    registry_address: &str,
    registry_key: &str,
) -> Option<DataCommand> {
    transactions.iter().rev().find_map(|transaction| {
        let receiver = transaction.receiver.as_deref()?;
        if normalize_hash(receiver, 20).ok()?.as_str() != registry_address {
            return None;
        }
        let command = decode_data_command(transaction.data.as_deref()?).ok()?;
        (command.key == registry_key).then_some(command)
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use ri_core::{IssuerKeyRegistry, RegistryFinalityTypeV2, resolver_id_key, sign_ed25519};

    use super::{
        MAX_TEXT_FIELD_BYTES, NORN_REGISTRY_SNAPSHOT_V1, NornAdapterConfig, NornRegistryAdapter,
        NornRegistrySnapshotEntryV1, NornRegistrySnapshotV1, SnapshotPins,
        confirmation_derived_height, decode_data_command, norn_registry_schema_hash,
        norn_state_root, registry_command, require_agreement, snapshot_records,
        validate_snapshot_shape,
    };
    use crate::{FinalizedCheckpoint, norn::Transaction};

    const GENESIS: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const ADDRESS: &str = "0x2222222222222222222222222222222222222222";
    const CHECKPOINT: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
    const OBJECT: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
    const ENDPOINT: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";

    fn signed_snapshot() -> (NornRegistrySnapshotV1, IssuerKeyRegistry) {
        let private = [7_u8; 32];
        let key = SigningKey::from_bytes(&private);
        let private_b64 = STANDARD.encode(private);
        let entries = vec![NornRegistrySnapshotEntryV1 {
            server_id: "operator/L01/r1".into(),
            resolver_id_key: resolver_id_key("operator/L01/r1"),
            object_hash: OBJECT.into(),
            object_version: 1,
            valid_until: 1_700_003_600,
            status: "ACTIVE".into(),
            endpoint_keys: vec![ENDPOINT.into()],
        }];
        let mut snapshot = NornRegistrySnapshotV1 {
            schema_version: NORN_REGISTRY_SNAPSHOT_V1.into(),
            chain_id: 20_001,
            genesis_block_hash: GENESIS.into(),
            registry_address: ADDRESS.into(),
            registry_key: "resolver-identity-registry-v2".into(),
            registry_schema_hash: norn_registry_schema_hash(),
            snapshot_version: 1,
            checkpoint_height: 100,
            checkpoint_hash: CHECKPOINT.into(),
            state_root: norn_state_root(&entries).unwrap(),
            root_status: "ACTIVE".into(),
            published_at: 1_699_999_900,
            valid_until: 1_700_003_600,
            issuer: "norn-registry".into(),
            key_id: "snapshot-key-1".into(),
            entries,
            signature: None,
        };
        snapshot.signature = Some(sign_ed25519(&snapshot, &private_b64).unwrap());
        let mut keys = IssuerKeyRegistry::default();
        keys.insert(
            "norn-registry",
            "snapshot-key-1",
            STANDARD.encode(key.verifying_key().to_bytes()),
        );
        (snapshot, keys)
    }

    #[test]
    fn signed_snapshot_pins_and_records_validate() {
        let (snapshot, keys) = signed_snapshot();
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        validate_snapshot_shape(
            &snapshot,
            &keys,
            &SnapshotPins {
                chain_id: 20_001,
                genesis_block_hash: GENESIS,
                registry_address: ADDRESS,
                registry_key: "resolver-identity-registry-v2",
                registry_schema_hash: &norn_registry_schema_hash(),
                signer_issuer: "norn-registry",
                signer_key_id: "snapshot-key-1",
                accepted_checkpoint: &checkpoint,
                now: 1_700_000_000,
            },
        )
        .unwrap();
        let records = snapshot_records(&snapshot).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records["operator/L01/r1"].resolver_id_key,
            resolver_id_key("operator/L01/r1")
        );
    }

    #[test]
    fn changed_genesis_and_signature_fail_closed() {
        let (mut snapshot, keys) = signed_snapshot();
        snapshot.genesis_block_hash =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        snapshot.signature = Some(sign_ed25519(&snapshot, &STANDARD.encode([7_u8; 32])).unwrap());
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        assert!(
            validate_snapshot_shape(
                &snapshot,
                &keys,
                &SnapshotPins {
                    chain_id: 20_001,
                    genesis_block_hash: GENESIS,
                    registry_address: ADDRESS,
                    registry_key: "resolver-identity-registry-v2",
                    registry_schema_hash: &norn_registry_schema_hash(),
                    signer_issuer: "norn-registry",
                    signer_key_id: "snapshot-key-1",
                    accepted_checkpoint: &checkpoint,
                    now: 1_700_000_000,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn changed_snapshot_payload_fails_signature_verification() {
        let (mut snapshot, keys) = signed_snapshot();
        snapshot.entries[0].object_hash =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        assert!(
            validate_snapshot_shape(
                &snapshot,
                &keys,
                &SnapshotPins {
                    chain_id: 20_001,
                    genesis_block_hash: GENESIS,
                    registry_address: ADDRESS,
                    registry_key: "resolver-identity-registry-v2",
                    registry_schema_hash: &norn_registry_schema_hash(),
                    signer_issuer: "norn-registry",
                    signer_key_id: "snapshot-key-1",
                    accepted_checkpoint: &checkpoint,
                    now: 1_700_000_000,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn dual_node_disagreement_and_insufficient_confirmations_fail_closed() {
        let checkpoint = FinalizedCheckpoint {
            number: 100,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        let mut divergent = checkpoint.clone();
        divergent.hash =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(
            require_agreement(
                vec![checkpoint, divergent],
                "Norn RPC checkpoint disagreement"
            )
            .is_err()
        );
        assert!(require_agreement(vec![GENESIS, "0xother"], "Norn genesis disagreement").is_err());
        assert_eq!(confirmation_derived_height(&[110, 108], 8).unwrap(), 100);
        assert!(confirmation_derived_height(&[8, 10], 8).is_err());
        assert!(confirmation_derived_height(&[7, 10], 8).is_err());
    }

    #[test]
    fn snapshot_ahead_of_confirmed_height_fails_closed() {
        let (mut snapshot, keys) = signed_snapshot();
        snapshot.checkpoint_height = 111;
        snapshot.signature = Some(sign_ed25519(&snapshot, &STANDARD.encode([7_u8; 32])).unwrap());
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        assert!(
            validate_snapshot_shape(
                &snapshot,
                &keys,
                &SnapshotPins {
                    chain_id: 20_001,
                    genesis_block_hash: GENESIS,
                    registry_address: ADDRESS,
                    registry_key: "resolver-identity-registry-v2",
                    registry_schema_hash: &norn_registry_schema_hash(),
                    signer_issuer: "norn-registry",
                    signer_key_id: "snapshot-key-1",
                    accepted_checkpoint: &checkpoint,
                    now: 1_700_000_000,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_field_limits_fail_closed() {
        let (mut snapshot, keys) = signed_snapshot();
        snapshot.entries[0].server_id = "x".repeat(MAX_TEXT_FIELD_BYTES + 1);
        snapshot.entries[0].resolver_id_key = resolver_id_key(&snapshot.entries[0].server_id);
        snapshot.state_root = norn_state_root(&snapshot.entries).unwrap();
        snapshot.signature = Some(sign_ed25519(&snapshot, &STANDARD.encode([7_u8; 32])).unwrap());
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        assert!(
            validate_snapshot_shape(
                &snapshot,
                &keys,
                &SnapshotPins {
                    chain_id: 20_001,
                    genesis_block_hash: GENESIS,
                    registry_address: ADDRESS,
                    registry_key: "resolver-identity-registry-v2",
                    registry_schema_hash: &norn_registry_schema_hash(),
                    signer_issuer: "norn-registry",
                    signer_key_id: "snapshot-key-1",
                    accepted_checkpoint: &checkpoint,
                    now: 1_700_000_000,
                },
            )
            .is_ok()
        );
        assert!(snapshot_records(&snapshot).is_err());
    }

    #[test]
    fn snapshot_signer_is_pinned_and_rotation_is_explicit() {
        let (old_snapshot, mut keys) = signed_snapshot();
        let checkpoint = FinalizedCheckpoint {
            number: 110,
            hash: CHECKPOINT.into(),
            finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        };
        let old_pins = SnapshotPins {
            chain_id: 20_001,
            genesis_block_hash: GENESIS,
            registry_address: ADDRESS,
            registry_key: "resolver-identity-registry-v2",
            registry_schema_hash: &norn_registry_schema_hash(),
            signer_issuer: "norn-registry",
            signer_key_id: "snapshot-key-1",
            accepted_checkpoint: &checkpoint,
            now: 1_700_000_000,
        };
        assert!(validate_snapshot_shape(&old_snapshot, &keys, &old_pins).is_ok());

        let private = [8_u8; 32];
        let signing_key = SigningKey::from_bytes(&private);
        let mut rotated = old_snapshot.clone();
        rotated.snapshot_version = 2;
        rotated.key_id = "snapshot-key-2".into();
        rotated.signature = None;
        rotated.signature = Some(sign_ed25519(&rotated, &STANDARD.encode(private)).unwrap());
        keys.insert(
            "norn-registry",
            "snapshot-key-2",
            STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );
        assert!(validate_snapshot_shape(&rotated, &keys, &old_pins).is_err());
        let rotated_pins = SnapshotPins {
            signer_key_id: "snapshot-key-2",
            ..old_pins
        };
        assert!(validate_snapshot_shape(&old_snapshot, &keys, &rotated_pins).is_err());
        assert!(validate_snapshot_shape(&rotated, &keys, &rotated_pins).is_ok());
    }

    #[test]
    fn go_norn_karmem_data_command_is_decoded_with_bounds_checks() {
        let fields = [b"set".as_slice(), b"registry-key", br#"{"version":1}"#];
        let mut encoded = vec![0_u8; 48];
        encoded[..4].copy_from_slice(&40_u32.to_le_bytes());
        for (header, field) in [4_usize, 16, 28].into_iter().zip(fields) {
            let offset = u32::try_from(encoded.len()).unwrap();
            encoded[header..header + 4].copy_from_slice(&offset.to_le_bytes());
            encoded[header + 4..header + 8]
                .copy_from_slice(&u32::try_from(field.len()).unwrap().to_le_bytes());
            encoded[header + 8..header + 12].copy_from_slice(&1_u32.to_le_bytes());
            encoded.extend_from_slice(field);
        }
        let command = decode_data_command(&format!("0x{}", hex::encode(&encoded))).unwrap();
        assert_eq!(command.operation, "set");
        assert_eq!(command.key, "registry-key");
        assert_eq!(command.value, r#"{"version":1}"#);
        assert!(decode_data_command("0x00").is_err());
    }

    #[test]
    fn malformed_norn_transactions_do_not_mask_latest_valid_publication() {
        let valid_data = {
            let fields = [b"set".as_slice(), b"registry-key", br#"{"version":1}"#];
            let mut encoded = vec![0_u8; 48];
            encoded[..4].copy_from_slice(&40_u32.to_le_bytes());
            for (header, field) in [4_usize, 16, 28].into_iter().zip(fields) {
                let offset = u32::try_from(encoded.len()).unwrap();
                encoded[header..header + 4].copy_from_slice(&offset.to_le_bytes());
                encoded[header + 4..header + 8]
                    .copy_from_slice(&u32::try_from(field.len()).unwrap().to_le_bytes());
                encoded[header + 8..header + 12].copy_from_slice(&1_u32.to_le_bytes());
                encoded.extend_from_slice(field);
            }
            format!("0x{}", hex::encode(encoded))
        };
        let transactions = vec![
            Transaction {
                hash: Some("0x01".into()),
                receiver: Some(ADDRESS.into()),
                data: Some(valid_data),
            },
            Transaction {
                hash: Some("0x02".into()),
                receiver: Some(ADDRESS.into()),
                data: Some("0x".into()),
            },
        ];
        let command = registry_command(&transactions, ADDRESS, "registry-key").unwrap();
        assert_eq!(command.operation, "set");
        assert_eq!(command.value, r#"{"version":1}"#);
    }

    #[tokio::test]
    async fn production_norn_requires_two_https_read_nodes() {
        let config = |rpc_urls| NornAdapterConfig {
            rpc_urls,
            chain_id: 20_001,
            genesis_block_hash: GENESIS.into(),
            registry_address: ADDRESS.into(),
            registry_key: "resolver-identity-registry-v2".into(),
            registry_schema_hash: norn_registry_schema_hash(),
            snapshot_signer_issuer: "norn-registry".into(),
            snapshot_signer_key_id: "snapshot-key-1".into(),
            confirmations: 12,
            registry_start_height: 0,
            max_scan_blocks: 10_000,
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: Some(super::NornClientTlsMaterial {
                ca_certificate_pem: b"test-ca".to_vec(),
                client_certificate_pem: b"test-cert".to_vec(),
                client_private_key_pem: b"test-key".to_vec(),
            }),
            production: true,
        };
        assert!(NornRegistryAdapter::new(config(vec!["https://node-a.example".into()])).is_err());
        assert!(
            NornRegistryAdapter::new(config(vec![
                "http://node-a.example".into(),
                "http://node-b.example".into(),
            ]))
            .is_err()
        );
        assert!(
            NornRegistryAdapter::new(config(vec![
                "https://node-a.example".into(),
                "https://node-b.example".into(),
            ]))
            .is_err()
        );
        let development = NornAdapterConfig {
            rpc_urls: vec!["http://127.0.0.1:45555".into()],
            chain_id: 20_001,
            genesis_block_hash: GENESIS.into(),
            registry_address: ADDRESS.into(),
            registry_key: "resolver-identity-registry-v2".into(),
            registry_schema_hash: norn_registry_schema_hash(),
            snapshot_signer_issuer: "norn-registry".into(),
            snapshot_signer_key_id: "snapshot-key-1".into(),
            confirmations: 12,
            registry_start_height: 0,
            max_scan_blocks: 10_000,
            request_timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4_194_304,
            tls: None,
            production: false,
        };
        assert!(NornRegistryAdapter::new(development.clone()).is_err());
        let two_nodes = NornAdapterConfig {
            rpc_urls: vec![
                "http://127.0.0.1:45555".into(),
                "http://127.0.0.1:45556".into(),
            ],
            ..development
        };
        assert!(NornRegistryAdapter::new(two_nodes).is_ok());
    }
}
