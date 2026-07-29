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
pub struct RegistryReferenceV2 {
    pub chain_id: u64,
    pub contract_address: String,
    pub contract_code_hash: String,
    pub finalized_block: u64,
    pub finalized_block_hash: String,
    pub state_root: String,
    pub object_hash: String,
    pub object_version: u64,
    pub resolver_status: String,
    pub root_status: String,
    pub endpoint_binding_status: String,
    pub snapshot_generation: u64,
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
