use serde::{Deserialize, Serialize};

use crate::endpoint::DnsEndpoint;

pub const DNS_SERVER_IDENTITY_V2: &str = "dns-server-identity-v2";
pub const SERVER_HOP_EVIDENCE_V2: &str = "dns-server-hop-evidence-v2";
pub const TARGET_RESPONSE_ATTESTATION_V2: &str = "dns-target-response-attestation-v2";
pub const QUERY_EVIDENCE_GRAPH_V2: &str = "dns-query-evidence-graph-v2";
pub const TRACE_EVENT_V2: &str = "dns-query-trace-event-v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnsServerRole {
    Recursive,
    Forwarder,
    RootAuthority,
    TldAuthority,
    Authoritative,
}

impl DnsServerRole {
    pub fn is_authority(self) -> bool {
        matches!(
            self,
            Self::RootAuthority | Self::TldAuthority | Self::Authoritative
        )
    }

    pub fn is_recursive(self) -> bool {
        matches!(self, Self::Recursive | Self::Forwarder)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationMode {
    ControlledStrict,
    PublicHybrid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLevel {
    AgentAttested,
    DnssecValidated,
    RegistryBound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceEventKind {
    ClientQuery,
    ResolverQuery,
    ResolverResponse,
    AuthorityQuery,
    AuthorityResponse,
    CacheHit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceEventV2 {
    pub schema_version: String,
    pub event_id: String,
    pub trace_id: String,
    pub correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    pub kind: TraceEventKind,
    pub observer_server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_server_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_endpoint: Option<DnsEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_correlation_id: Option<String>,
    pub query_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    pub observed_at: i64,
    pub dnssec_status: DnssecStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_graph_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentBindingV2 {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsServerIdentityV2 {
    pub schema_version: String,
    pub server_id: String,
    pub operator_id: String,
    pub role: DnsServerRole,
    pub endpoints: Vec<DnsEndpoint>,
    #[serde(default)]
    pub anycast: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anycast_service_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentBindingV2>,
    pub valid_from: i64,
    pub valid_until: i64,
    pub object_version: u64,
    pub status: String,
    pub issuer: String,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl DnsServerIdentityV2 {
    pub fn active_at(&self, now: i64) -> bool {
        self.status == "ACTIVE" && self.valid_from <= now && now <= self.valid_until
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "adapter_type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegistryAdapterMetadataV2 {
    Evm {
        chain_id: u64,
        contract_address: String,
        runtime_code_hash: String,
    },
    Norn {
        genesis_block_hash: String,
        registry_address: String,
        registry_key: String,
        snapshot_signer_issuer: String,
        snapshot_signer_key_id: String,
    },
    External {
        driver: String,
        snapshot_signer_issuer: String,
        snapshot_signer_key_id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryFinalityTypeV2 {
    EvmFinalized,
    EvmConfirmations,
    EvmFinalizedOrConfirmations,
    NornDualNodeConfirmations,
    ExternalSignedCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistryReferenceV2 {
    /// Explicit adapter name. Missing values fail deserialization; there is no
    /// implicit downgrade to EVM.
    pub chain_adapter: String,
    /// Stable chain identity, for example `eip155:11155111` or
    /// `norn-genesis:0x...`.
    pub chain_identity: String,
    /// Adapter-specific Registry locator in a human-auditable canonical form.
    pub registry_locator: String,
    /// Identity of the Registry runtime or snapshot schema.
    pub registry_schema_hash: String,
    /// Chain-specific values are typed and never overloaded across adapters.
    pub adapter_metadata: RegistryAdapterMetadataV2,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub finality_type: RegistryFinalityTypeV2,
    pub state_root: String,
    pub object_hash: String,
    pub object_version: u64,
    pub resolver_status: String,
    pub root_status: String,
    pub endpoint_binding_status: String,
    pub snapshot_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryReferenceWire {
    #[serde(default)]
    chain_adapter: String,
    #[serde(default)]
    chain_identity: String,
    #[serde(default)]
    registry_locator: String,
    #[serde(default)]
    registry_schema_hash: String,
    #[serde(default)]
    adapter_metadata: Option<RegistryAdapterMetadataV2>,
    #[serde(default, alias = "chain_id")]
    evm_chain_id: Option<u64>,
    #[serde(default, alias = "contract_address")]
    evm_contract_address: Option<String>,
    #[serde(default, alias = "contract_code_hash")]
    evm_runtime_code_hash: Option<String>,
    #[serde(alias = "finalized_block")]
    checkpoint_height: u64,
    #[serde(alias = "finalized_block_hash")]
    checkpoint_hash: String,
    #[serde(default)]
    finality_type: Option<RegistryFinalityTypeV2>,
    state_root: String,
    object_hash: String,
    object_version: u64,
    resolver_status: String,
    root_status: String,
    endpoint_binding_status: String,
    snapshot_generation: u64,
}

impl<'de> Deserialize<'de> for RegistryReferenceV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let wire = RegistryReferenceWire::deserialize(deserializer)?;
        let legacy_evm_present = wire.evm_chain_id.is_some()
            || wire.evm_contract_address.is_some()
            || wire.evm_runtime_code_hash.is_some();
        let typed_metadata_present = wire.adapter_metadata.is_some();
        if typed_metadata_present && wire.chain_adapter.is_empty() {
            return Err(D::Error::custom(
                "chain_adapter is required with typed adapter metadata",
            ));
        }
        let legacy_evm_reference = !typed_metadata_present && legacy_evm_present;
        let adapter_metadata = match (wire.adapter_metadata, legacy_evm_present) {
            (Some(_), true) => {
                return Err(D::Error::custom(
                    "typed adapter metadata conflicts with legacy EVM fields",
                ));
            }
            (Some(metadata), false) => metadata,
            (None, true) if wire.chain_adapter.is_empty() || wire.chain_adapter == "evm" => {
                RegistryAdapterMetadataV2::Evm {
                    chain_id: wire
                        .evm_chain_id
                        .ok_or_else(|| D::Error::custom("legacy EVM chain ID is incomplete"))?,
                    contract_address: wire.evm_contract_address.ok_or_else(|| {
                        D::Error::custom("legacy EVM contract address is incomplete")
                    })?,
                    runtime_code_hash: wire.evm_runtime_code_hash.ok_or_else(|| {
                        D::Error::custom("legacy EVM runtime code hash is incomplete")
                    })?,
                }
            }
            (None, _) => {
                return Err(D::Error::custom(
                    "typed adapter metadata is required for non-legacy references",
                ));
            }
        };
        let (chain_adapter, chain_identity, registry_locator, registry_schema_hash) =
            match &adapter_metadata {
                RegistryAdapterMetadataV2::Evm {
                    chain_id,
                    contract_address,
                    runtime_code_hash,
                } => (
                    if wire.chain_adapter.is_empty() {
                        "evm".into()
                    } else {
                        wire.chain_adapter
                    },
                    if wire.chain_identity.is_empty() {
                        format!("eip155:{chain_id}")
                    } else {
                        wire.chain_identity
                    },
                    if wire.registry_locator.is_empty() {
                        format!("evm:{contract_address}")
                    } else {
                        wire.registry_locator
                    },
                    if wire.registry_schema_hash.is_empty() {
                        runtime_code_hash.clone()
                    } else {
                        wire.registry_schema_hash
                    },
                ),
                _ => (
                    wire.chain_adapter,
                    wire.chain_identity,
                    wire.registry_locator,
                    wire.registry_schema_hash,
                ),
            };
        let finality_type = match wire.finality_type {
            Some(value) => value,
            None if legacy_evm_reference => RegistryFinalityTypeV2::EvmFinalizedOrConfirmations,
            None => {
                return Err(D::Error::custom(
                    "finality_type is required for typed Registry references",
                ));
            }
        };
        let target_matches_metadata = match &adapter_metadata {
            RegistryAdapterMetadataV2::Evm {
                chain_id,
                contract_address,
                runtime_code_hash,
            } => {
                chain_adapter == "evm"
                    && chain_identity == format!("eip155:{chain_id}")
                    && registry_locator == format!("evm:{contract_address}")
                    && registry_schema_hash == *runtime_code_hash
                    && matches!(
                        finality_type,
                        RegistryFinalityTypeV2::EvmFinalized
                            | RegistryFinalityTypeV2::EvmConfirmations
                            | RegistryFinalityTypeV2::EvmFinalizedOrConfirmations
                    )
            }
            RegistryAdapterMetadataV2::Norn {
                genesis_block_hash,
                registry_address,
                registry_key,
                ..
            } => {
                chain_adapter == "norn"
                    && chain_identity == format!("norn-genesis:{genesis_block_hash}")
                    && registry_locator == format!("norn:{registry_address}#{registry_key}")
                    && !registry_schema_hash.is_empty()
                    && finality_type == RegistryFinalityTypeV2::NornDualNodeConfirmations
            }
            RegistryAdapterMetadataV2::External { driver, .. } => {
                chain_adapter == "external"
                    && !driver.is_empty()
                    && !chain_identity.is_empty()
                    && !registry_locator.is_empty()
                    && !registry_schema_hash.is_empty()
                    && finality_type == RegistryFinalityTypeV2::ExternalSignedCheckpoint
            }
        };
        if !target_matches_metadata {
            return Err(D::Error::custom(
                "Registry target fields conflict with typed adapter metadata",
            ));
        }
        Ok(Self {
            chain_adapter,
            chain_identity,
            registry_locator,
            registry_schema_hash,
            adapter_metadata,
            checkpoint_height: wire.checkpoint_height,
            checkpoint_hash: wire.checkpoint_hash,
            finality_type,
            state_root: wire.state_root,
            object_hash: wire.object_hash,
            object_version: wire.object_version,
            resolver_status: wire.resolver_status,
            root_status: wire.root_status,
            endpoint_binding_status: wire.endpoint_binding_status,
            snapshot_generation: wire.snapshot_generation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetResponseAttestationV2 {
    pub schema_version: String,
    pub target_server_id: String,
    pub trace_id: String,
    pub correlation_id: String,
    pub challenge: String,
    pub query_digest: String,
    pub response_digest: String,
    pub endpoint: DnsEndpoint,
    pub observed_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerHopEvidenceV2 {
    pub schema_version: String,
    pub edge_id: String,
    pub trace_id: String,
    pub target_correlation_id: String,
    pub challenge: String,
    pub from_server_id: String,
    pub to_server_id: String,
    pub from_endpoint: DnsEndpoint,
    pub to_endpoint: DnsEndpoint,
    pub query_digest: String,
    pub response_digest: String,
    pub observed_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub accepted: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub registry: RegistryReferenceV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_attestation: Option<TargetResponseAttestationV2>,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceNodeV2 {
    pub identity: DnsServerIdentityV2,
    pub registry: RegistryReferenceV2,
    #[serde(default)]
    pub evidence_levels: Vec<EvidenceLevel>,
    pub accepted: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheProvenanceV2 {
    pub source_graph_digest: String,
    pub source_dnssec_required: bool,
    pub cached_at: i64,
    pub dns_ttl_expires_at: i64,
    pub identity_expires_at: i64,
    pub snapshot_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryEvidenceGraphV2 {
    pub schema_version: String,
    pub trace_id: String,
    pub correlation_id: String,
    pub challenge: String,
    pub query_digest: String,
    pub response_digest: String,
    pub mode: VerificationMode,
    pub entry_server_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub dnssec_status: DnssecStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_provenance: Option<CacheProvenanceV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_cache_graphs: Vec<QueryEvidenceGraphV2>,
    pub nodes: Vec<EvidenceNodeV2>,
    pub edges: Vec<ServerHopEvidenceV2>,
    pub terminal_node_ids: Vec<String>,
    pub final_result: bool,
    #[serde(default)]
    pub graph_errors: Vec<String>,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::RegistryReferenceV2;

    fn external_reference() -> Value {
        json!({
            "chain_adapter": "external",
            "chain_identity": "fabric:channel-a:genesis-a",
            "registry_locator": "fabric:channel-a/identity-registry",
            "registry_schema_hash":
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            "adapter_metadata": {
                "adapter_type": "external",
                "driver": "fabric",
                "snapshot_signer_issuer": "adapter-operator",
                "snapshot_signer_key_id": "adapter-key-1"
            },
            "checkpoint_height": 10,
            "checkpoint_hash":
                "0x2222222222222222222222222222222222222222222222222222222222222222",
            "finality_type": "external-signed-checkpoint",
            "state_root":
                "0x3333333333333333333333333333333333333333333333333333333333333333",
            "object_hash":
                "0x4444444444444444444444444444444444444444444444444444444444444444",
            "object_version": 1,
            "resolver_status": "ACTIVE",
            "root_status": "ACTIVE",
            "endpoint_binding_status": "MATCHED",
            "snapshot_generation": 1
        })
    }

    #[test]
    fn typed_registry_reference_rejects_adapter_metadata_confusion() {
        let mut value = external_reference();
        value["chain_adapter"] = json!("norn");
        assert!(serde_json::from_value::<RegistryReferenceV2>(value).is_err());

        let mut value = external_reference();
        value["finality_type"] = json!("evm-finalized");
        assert!(serde_json::from_value::<RegistryReferenceV2>(value).is_err());

        let mut value = external_reference();
        value.as_object_mut().unwrap().remove("finality_type");
        assert!(serde_json::from_value::<RegistryReferenceV2>(value).is_err());
    }

    #[test]
    fn legacy_evm_reference_migrates_only_complete_evm_fields() {
        let legacy = json!({
            "chain_id": 11155111,
            "contract_address": "0x1111111111111111111111111111111111111111",
            "contract_code_hash":
                "0x2222222222222222222222222222222222222222222222222222222222222222",
            "finalized_block": 10,
            "finalized_block_hash":
                "0x3333333333333333333333333333333333333333333333333333333333333333",
            "state_root":
                "0x4444444444444444444444444444444444444444444444444444444444444444",
            "object_hash":
                "0x5555555555555555555555555555555555555555555555555555555555555555",
            "object_version": 1,
            "resolver_status": "ACTIVE",
            "root_status": "ACTIVE",
            "endpoint_binding_status": "MATCHED",
            "snapshot_generation": 1
        });
        let migrated = serde_json::from_value::<RegistryReferenceV2>(legacy).unwrap();
        assert_eq!(migrated.chain_adapter, "evm");
        assert_eq!(migrated.chain_identity, "eip155:11155111");

        let mut conflicting = serde_json::to_value(migrated).unwrap();
        conflicting["chain_id"] = json!(1);
        assert!(serde_json::from_value::<RegistryReferenceV2>(conflicting).is_err());
    }
}
