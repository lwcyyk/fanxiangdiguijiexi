pub mod canonical;
pub mod crypto;
pub mod endpoint;
pub mod evidence;
pub mod policy;

pub use canonical::{canonical_json_bytes, canonical_json_text, strip_signatures};
pub use crypto::{
    ED25519_PREFIX, dns_correlation_id, dns_wire_digest, ed25519_public_key_b64, object_hash,
    resolver_id_key, sha256_hex, sign_ed25519, verify_ed25519,
};
pub use endpoint::DnsEndpoint;
pub use evidence::{
    AgentBindingV2, CacheProvenanceV2, DnsServerIdentityV2, DnsServerRole, DnssecStatus,
    EvidenceLevel, EvidenceNodeV2, QueryEvidenceGraphV2, RegistryReferenceV2, ServerHopEvidenceV2,
    TargetResponseAttestationV2, TraceEventKind, TraceEventV2, VerificationMode,
};
pub use policy::{EvidencePolicy, EvidenceValidationError, EvidenceValidator, IssuerKeyRegistry};
