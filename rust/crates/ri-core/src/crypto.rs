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

pub fn dns_cache_object_digest(message: &[u8]) -> Result<String, EvidenceValidationError> {
    if message.len() < 12 {
        return Err(EvidenceValidationError::InvalidGraph(
            "DNS message is too short for cache normalization".into(),
        ));
    }
    let mut normalized = message.to_vec();
    normalized[0] = 0;
    normalized[1] = 0;
    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let record_count = usize::from(u16::from_be_bytes([message[6], message[7]]))
        + usize::from(u16::from_be_bytes([message[8], message[9]]))
        + usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_dns_name(message, offset)?;
        offset = offset.checked_add(4).ok_or_else(|| {
            EvidenceValidationError::InvalidGraph("DNS question offset overflow".into())
        })?;
        if offset > message.len() {
            return Err(EvidenceValidationError::InvalidGraph(
                "DNS question exceeds message boundary".into(),
            ));
        }
    }
    for _ in 0..record_count {
        offset = skip_dns_name(message, offset)?;
        if offset.checked_add(10).is_none_or(|end| end > message.len()) {
            return Err(EvidenceValidationError::InvalidGraph(
                "DNS resource record header exceeds message boundary".into(),
            ));
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        if record_type != 41 {
            normalized[offset + 4..offset + 8].fill(0);
        }
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset = offset
            .checked_add(10)
            .and_then(|value| value.checked_add(data_length))
            .ok_or_else(|| {
                EvidenceValidationError::InvalidGraph("DNS resource record offset overflow".into())
            })?;
        if offset > message.len() {
            return Err(EvidenceValidationError::InvalidGraph(
                "DNS resource record exceeds message boundary".into(),
            ));
        }
    }
    Ok(sha256_hex(normalized))
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Result<usize, EvidenceValidationError> {
    for _ in 0..128 {
        let length = *message.get(offset).ok_or_else(|| {
            EvidenceValidationError::InvalidGraph("DNS name exceeds message boundary".into())
        })?;
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= message.len() {
                return Err(EvidenceValidationError::InvalidGraph(
                    "DNS compression pointer is truncated".into(),
                ));
            }
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(message[offset + 1]);
            if pointer >= message.len() {
                return Err(EvidenceValidationError::InvalidGraph(
                    "DNS compression pointer exceeds message boundary".into(),
                ));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(EvidenceValidationError::InvalidGraph(
                "DNS name contains an invalid label".into(),
            ));
        }
        offset = offset.checked_add(1 + usize::from(length)).ok_or_else(|| {
            EvidenceValidationError::InvalidGraph("DNS name offset overflow".into())
        })?;
        if offset > message.len() {
            return Err(EvidenceValidationError::InvalidGraph(
                "DNS label exceeds message boundary".into(),
            ));
        }
    }
    Err(EvidenceValidationError::InvalidGraph(
        "DNS name has too many labels".into(),
    ))
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

#[cfg(test)]
mod tests {
    use super::dns_cache_object_digest;

    fn response(ttl: u32, address: [u8; 4]) -> Vec<u8> {
        let mut wire = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
        ];
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&[0x00, 0x04]);
        wire.extend_from_slice(&address);
        wire
    }

    #[test]
    fn cache_digest_ignores_transaction_id_and_ttl_only() {
        let first = response(300, [192, 0, 2, 1]);
        let mut aged = response(12, [192, 0, 2, 1]);
        aged[..2].copy_from_slice(&[0xab, 0xcd]);
        assert_eq!(
            dns_cache_object_digest(&first).unwrap(),
            dns_cache_object_digest(&aged).unwrap()
        );

        let changed = response(12, [192, 0, 2, 2]);
        assert_ne!(
            dns_cache_object_digest(&first).unwrap(),
            dns_cache_object_digest(&changed).unwrap()
        );
    }

    #[test]
    fn cache_digest_rejects_truncated_or_invalid_compression() {
        assert!(dns_cache_object_digest(&[0; 11]).is_err());
        let mut invalid = response(30, [192, 0, 2, 1]);
        invalid[19..21].copy_from_slice(&[0xff, 0xff]);
        assert!(dns_cache_object_digest(&invalid).is_err());
    }
}
