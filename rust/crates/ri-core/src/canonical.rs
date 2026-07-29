use serde_json::{Map, Value};

use crate::policy::EvidenceValidationError;

/// Matches the Python V1 behavior: recursively remove every field named
/// `signature`, sort object keys, and emit compact UTF-8 JSON.
pub fn strip_signatures(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object
                .keys()
                .filter(|key| key.as_str() != "signature")
                .collect::<Vec<_>>();
            keys.sort_unstable();
            let mut stripped = Map::new();
            for key in keys {
                stripped.insert(key.clone(), strip_signatures(&object[key]));
            }
            Value::Object(stripped)
        }
        Value::Array(items) => Value::Array(items.iter().map(strip_signatures).collect()),
        _ => value.clone(),
    }
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, EvidenceValidationError> {
    serde_json::to_vec(&strip_signatures(value))
        .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))
}

pub fn canonical_json_text(value: &Value) -> Result<String, EvidenceValidationError> {
    String::from_utf8(canonical_json_bytes(value)?)
        .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))
}
