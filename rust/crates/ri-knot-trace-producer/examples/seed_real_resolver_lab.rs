use std::env;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use ri_core::evidence::DNS_SERVER_IDENTITY_V2;
use ri_core::{
    AgentBindingV2, DnsEndpoint, DnsServerIdentityV2, DnsServerRole, RegistryAdapterMetadataV2,
    RegistryFinalityTypeV2, RegistryReferenceV2, ed25519_public_key_b64, object_hash, sha256_hex,
    sign_ed25519,
};
use ri_store::EvidenceStore;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        env::args()
            .nth(1)
            .ok_or("usage: seed_real_resolver_lab <output-directory>")?,
    );
    std::fs::create_dir_all(&output)?;
    let database = output.join("evidence-v2.db");
    let issuer_private = random_private_key();
    let agent_private = random_private_key();
    let issuer_public = ed25519_public_key_b64(&issuer_private)?;
    let agent_public = ed25519_public_key_b64(&agent_private)?;
    let now = unix_time();

    let recursive = signed_identity(
        "operator/L01/r1",
        DnsServerRole::Recursive,
        vec![
            endpoint("127.0.0.1", 15354, "udp"),
            endpoint("127.0.0.1", 15354, "tcp"),
        ],
        Some(AgentBindingV2 {
            key_id: "lab-agent-key".into(),
            algorithm: "ed25519".into(),
            public_key: agent_public,
            service_url: Some("http://127.0.0.1:18443".into()),
        }),
        &issuer_private,
        now,
    )?;
    let authority = signed_identity(
        "authority/trace-root",
        DnsServerRole::RootAuthority,
        vec![
            endpoint("127.0.0.2", 15353, "udp"),
            endpoint("127.0.0.2", 15353, "tcp"),
            endpoint("127.0.0.3", 15353, "udp"),
            endpoint("127.0.0.4", 15353, "udp"),
        ],
        None,
        &issuer_private,
        now,
    )?;
    let deployment = Deployment {
        genesis: sha256_hex(b"production-resolver-trace-lab-genesis"),
        registry_address: "0x1111111111111111111111111111111111111111".into(),
        registry_key: "resolver-identities-v2".into(),
        schema_hash: sha256_hex(b"resolver-identity-trace-lab-schema-v1"),
        checkpoint_hash: sha256_hex(b"production-resolver-trace-lab-checkpoint"),
        state_root: sha256_hex(b"production-resolver-trace-lab-state"),
    };
    let records = vec![
        (recursive.clone(), registry(&recursive, &deployment)?),
        (authority.clone(), registry(&authority, &deployment)?),
    ];
    let store = EvidenceStore::open(&database)?;
    store.apply_registry_snapshot(&records, now)?;

    write_secret(&output.join("agent_private_key"), &agent_private)?;
    write_secret(
        &output.join("trace_ingest_token"),
        &random_token("trace-ingest"),
    )?;
    write_secret(
        &output.join("agent_wrapper_token"),
        &random_token("agent-wrapper"),
    )?;
    write_secret(
        &output.join("agent_peer_token"),
        &random_token("agent-peer"),
    )?;
    std::fs::write(
        output.join("issuer-keys.json"),
        serde_json::to_vec_pretty(&json!({
            "keys": [{
                "issuer": "trace-lab-issuer",
                "key_id": "trace-lab-issuer-key",
                "algorithm": "ed25519",
                "public_key": issuer_public
            }]
        }))?,
    )?;
    std::fs::write(
        output.join("seed-manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "database": database,
            "server_id": recursive.server_id,
            "authority_server_id": authority.server_id,
            "registry_adapter": "norn",
            "checkpoint_height": 100,
            "generated_at": now
        }))?,
    )?;
    Ok(())
}

struct Deployment {
    genesis: String,
    registry_address: String,
    registry_key: String,
    schema_hash: String,
    checkpoint_hash: String,
    state_root: String,
}

fn signed_identity(
    server_id: &str,
    role: DnsServerRole,
    endpoints: Vec<DnsEndpoint>,
    agent: Option<AgentBindingV2>,
    issuer_private: &str,
    now: i64,
) -> Result<DnsServerIdentityV2, Box<dyn std::error::Error>> {
    let mut identity = DnsServerIdentityV2 {
        schema_version: DNS_SERVER_IDENTITY_V2.into(),
        server_id: server_id.into(),
        operator_id: "trace-lab-operator".into(),
        role,
        endpoints,
        anycast: role == DnsServerRole::RootAuthority,
        anycast_service_id: (role == DnsServerRole::RootAuthority)
            .then(|| "trace-root-service".into()),
        agent,
        valid_from: now - 60,
        valid_until: now + 3_600,
        object_version: 1,
        status: "ACTIVE".into(),
        issuer: "trace-lab-issuer".into(),
        key_id: "trace-lab-issuer-key".into(),
        signature: None,
    };
    identity.signature = Some(sign_ed25519(&identity, issuer_private)?);
    Ok(identity)
}

fn registry(
    identity: &DnsServerIdentityV2,
    deployment: &Deployment,
) -> Result<RegistryReferenceV2, Box<dyn std::error::Error>> {
    Ok(RegistryReferenceV2 {
        chain_adapter: "norn".into(),
        chain_identity: format!("norn-genesis:{}", deployment.genesis),
        registry_locator: format!(
            "norn:{}#{}",
            deployment.registry_address, deployment.registry_key
        ),
        registry_schema_hash: deployment.schema_hash.clone(),
        adapter_metadata: RegistryAdapterMetadataV2::Norn {
            genesis_block_hash: deployment.genesis.clone(),
            registry_address: deployment.registry_address.clone(),
            registry_key: deployment.registry_key.clone(),
            snapshot_signer_issuer: "trace-lab-issuer".into(),
            snapshot_signer_key_id: "trace-lab-issuer-key".into(),
        },
        checkpoint_height: 100,
        checkpoint_hash: deployment.checkpoint_hash.clone(),
        finality_type: RegistryFinalityTypeV2::NornDualNodeConfirmations,
        state_root: deployment.state_root.clone(),
        object_hash: object_hash(identity)?,
        object_version: identity.object_version,
        resolver_status: "ACTIVE".into(),
        root_status: "ACTIVE".into(),
        endpoint_binding_status: "MATCHED".into(),
        snapshot_generation: 1,
    })
}

fn endpoint(ip: &str, port: u16, transport: &str) -> DnsEndpoint {
    DnsEndpoint {
        endpoint_id: None,
        ip: Some(ip.into()),
        port: Some(port),
        transport: transport.into(),
        uri: None,
        server_name: None,
        alpn: vec![],
    }
}

fn random_private_key() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

fn random_token(label: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{label}-{}", hex::encode(bytes))
}

fn write_secret(path: &Path, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, format!("{value}\n"))?;
    std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}
