use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json_bytes;
use crate::policy::EvidenceValidationError;

pub const ED25519_PREFIX: &str = "base64:ed25519:";

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(Sha256::digest(data.as_ref())))
}

pub fn object_hash<T: Serialize>(value: &T) -> Result<String, EvidenceValidationError> {
    let json = serde_json::to_value(value)
        .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(canonical_json_bytes(&json)?))
}

pub fn resolver_id_key(resolver_id: &str) -> String {
    sha256_hex(format!("resolver-id:{}", normalize_name(resolver_id)))
}

pub fn dns_wire_digest(message: &[u8]) -> String {
    let mut normalized = message.to_vec();
    if normalized.len() >= 2 {
        normalized[0] = 0;
        normalized[1] = 0;
    }
    sha256_hex(normalized)
}

pub fn dns_correlation_id(message: &[u8]) -> Result<String, EvidenceValidationError> {
    if message.len() < 2 {
        return Err(EvidenceValidationError::InvalidGraph(
            "DNS message is too short for correlation".into(),
        ));
    }
    Ok(sha256_hex(format!(
        "dns-correlation-v2:{:02x}{:02x}:{}",
        message[0],
        message[1],
        dns_wire_digest(message)
    )))
}

pub fn sign_ed25519<T: Serialize>(
    value: &T,
    private_key_b64: &str,
) -> Result<String, EvidenceValidationError> {
    let private_raw = STANDARD
        .decode(private_key_b64)
        .map_err(|_| EvidenceValidationError::InvalidPrivateKey)?;
    let private_bytes: [u8; 32] = private_raw
        .try_into()
        .map_err(|_| EvidenceValidationError::InvalidPrivateKey)?;
    let key = SigningKey::from_bytes(&private_bytes);
    let json = serde_json::to_value(value)
        .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))?;
    let signature = key.sign(&canonical_json_bytes(&json)?);
    Ok(format!(
        "{ED25519_PREFIX}{}",
        STANDARD.encode(signature.to_bytes())
    ))
}

pub fn ed25519_public_key_b64(private_key_b64: &str) -> Result<String, EvidenceValidationError> {
    let private_raw = STANDARD
        .decode(private_key_b64)
        .map_err(|_| EvidenceValidationError::InvalidPrivateKey)?;
    let private_bytes: [u8; 32] = private_raw
        .try_into()
        .map_err(|_| EvidenceValidationError::InvalidPrivateKey)?;
    let key = SigningKey::from_bytes(&private_bytes);
    Ok(STANDARD.encode(key.verifying_key().to_bytes()))
}

pub fn verify_ed25519<T: Serialize>(
    value: &T,
    public_key_b64: &str,
) -> Result<(), EvidenceValidationError> {
    let json = serde_json::to_value(value)
        .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))?;
    let signature_text = json
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(EvidenceValidationError::MissingSignature)?;
    let encoded = signature_text
        .strip_prefix(ED25519_PREFIX)
        .ok_or(EvidenceValidationError::UnsupportedSignatureAlgorithm)?;
    let signature_raw = STANDARD
        .decode(encoded)
        .map_err(|_| EvidenceValidationError::InvalidSignature)?;
    let signature_bytes: [u8; 64] = signature_raw
        .try_into()
        .map_err(|_| EvidenceValidationError::InvalidSignature)?;
    let public_raw = STANDARD
        .decode(public_key_b64)
        .map_err(|_| EvidenceValidationError::InvalidPublicKey)?;
    let public_bytes: [u8; 32] = public_raw
        .try_into()
        .map_err(|_| EvidenceValidationError::InvalidPublicKey)?;
    let public_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| EvidenceValidationError::InvalidPublicKey)?;
    public_key
        .verify(
            &canonical_json_bytes(&json)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| EvidenceValidationError::InvalidSignature)
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_lowercase()
}
