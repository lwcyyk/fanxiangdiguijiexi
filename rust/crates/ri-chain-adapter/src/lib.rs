//! Chain-specific Registry reads behind one fail-closed compatibility layer.

mod evm;
mod external;
mod norn;

use std::collections::BTreeMap;

use async_trait::async_trait;
use ri_core::{
    DnsServerIdentityV2, IssuerKeyRegistry, RegistryAdapterMetadataV2, RegistryFinalityTypeV2,
    RegistryReferenceV2,
};

pub use evm::{EvmAdapterConfig, EvmRegistryAdapter};
pub use external::{
    EXTERNAL_REGISTRY_SNAPSHOT_V1, ExternalAdapterConfig, ExternalClientTlsMaterial,
    ExternalRegistryAdapter, ExternalRegistrySnapshotEntryV1, ExternalRegistrySnapshotV1,
};
pub use norn::{
    NORN_REGISTRY_SNAPSHOT_V1, NornAdapterConfig, NornClientTlsMaterial, NornDevelopmentClient,
    NornDevelopmentTransaction, NornRegistryAdapter, NornRegistrySnapshotEntryV1,
    NornRegistrySnapshotV1,
};

pub type AdapterError = Box<dyn std::error::Error + Send + Sync>;
pub type AdapterResult<T> = Result<T, AdapterError>;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainTarget {
    pub adapter: String,
    pub chain_identity: String,
    pub registry_locator: String,
    pub registry_schema_hash: String,
    pub adapter_metadata: RegistryAdapterMetadataV2,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCheckpoint {
    pub number: u64,
    pub hash: String,
    pub finality_type: RegistryFinalityTypeV2,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct RegistryRecord {
    pub resolver_id_key: String,
    pub object_hash: String,
    pub state_root: String,
    pub object_version: u64,
    pub valid_until: i64,
    pub resolver_status: String,
    pub root_status: String,
    /// Maps canonical endpoint Registry keys to Resolver ID keys.
    pub endpoint_owners: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainSnapshot {
    pub checkpoint: FinalizedCheckpoint,
    pub state_root: String,
    pub generation: u64,
    pub records: BTreeMap<String, RegistryRecord>,
}

#[async_trait]
pub trait RegistryChainAdapter: Send + Sync {
    fn target(&self) -> &ChainTarget;

    /// Return a complete, internally consistent Registry snapshot.
    async fn read_snapshot(
        &self,
        identities: &[DnsServerIdentityV2],
        issuer_keys: &IssuerKeyRegistry,
        now: i64,
    ) -> AdapterResult<ChainSnapshot>;

    /// Resolve a historical block hash for high-water-mark verification.
    async fn block_hash(&self, number: u64) -> AdapterResult<String>;
}

pub fn registry_reference(
    target: &ChainTarget,
    checkpoint: &FinalizedCheckpoint,
    generation: u64,
    record: RegistryRecord,
) -> RegistryReferenceV2 {
    RegistryReferenceV2 {
        chain_adapter: target.adapter.clone(),
        chain_identity: target.chain_identity.clone(),
        registry_locator: target.registry_locator.clone(),
        registry_schema_hash: target.registry_schema_hash.clone(),
        adapter_metadata: target.adapter_metadata.clone(),
        checkpoint_height: checkpoint.number,
        checkpoint_hash: checkpoint.hash.clone(),
        finality_type: checkpoint.finality_type,
        state_root: record.state_root,
        object_hash: record.object_hash,
        object_version: record.object_version,
        resolver_status: record.resolver_status,
        root_status: record.root_status,
        endpoint_binding_status: "MATCHED".into(),
        snapshot_generation: generation,
    }
}

pub(crate) fn normalize_hash(value: &str, bytes: usize) -> AdapterResult<String> {
    let normalized = value.to_ascii_lowercase();
    let raw = normalized
        .strip_prefix("0x")
        .ok_or("hex value lacks 0x prefix")?;
    if raw.len() != bytes * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("hex value must contain {bytes} bytes").into());
    }
    Ok(format!("0x{raw}"))
}

pub(crate) fn is_zero_hex(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|raw| raw.bytes().all(|byte| byte == b'0'))
}

pub(crate) fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ri_core::{RegistryAdapterMetadataV2, RegistryFinalityTypeV2};

    use super::{ChainTarget, FinalizedCheckpoint, RegistryRecord, registry_reference};

    #[test]
    fn non_evm_reference_does_not_serialize_evm_compatibility_fields() {
        let reference = registry_reference(
            &ChainTarget {
                adapter: "norn".into(),
                chain_identity:
                    "norn-genesis:0x1111111111111111111111111111111111111111111111111111111111111111"
                        .into(),
                registry_locator:
                    "norn:0x2222222222222222222222222222222222222222#identity-registry".into(),
                registry_schema_hash:
                    "0x3333333333333333333333333333333333333333333333333333333333333333"
                        .into(),
                adapter_metadata: RegistryAdapterMetadataV2::Norn {
                    genesis_block_hash:
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .into(),
                    registry_address: "0x2222222222222222222222222222222222222222".into(),
                    registry_key: "identity-registry".into(),
                    snapshot_signer_issuer: "norn-registry".into(),
                    snapshot_signer_key_id: "snapshot-key-1".into(),
                },
            },
            &FinalizedCheckpoint {
                number: 10,
                hash: "0x4444444444444444444444444444444444444444444444444444444444444444"
                    .into(),
                finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
            },
            1,
            RegistryRecord {
                resolver_id_key:
                    "0x5555555555555555555555555555555555555555555555555555555555555555"
                        .into(),
                object_hash:
                    "0x6666666666666666666666666666666666666666666666666666666666666666"
                        .into(),
                state_root:
                    "0x7777777777777777777777777777777777777777777777777777777777777777"
                        .into(),
                object_version: 1,
                valid_until: 2_000,
                resolver_status: "ACTIVE".into(),
                root_status: "ACTIVE".into(),
                endpoint_owners: BTreeMap::new(),
            },
        );
        let mut value = serde_json::to_value(reference).unwrap();
        assert_eq!(
            value["adapter_metadata"]["adapter_type"],
            serde_json::json!("norn")
        );
        assert!(value.get("chain_id").is_none());
        assert!(value.get("contract_address").is_none());
        assert!(value.get("contract_code_hash").is_none());
        value.as_object_mut().unwrap().remove("chain_adapter");
        assert!(serde_json::from_value::<ri_core::RegistryReferenceV2>(value).is_err());
    }
}
