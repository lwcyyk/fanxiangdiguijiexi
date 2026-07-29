use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::canonical::canonical_json_text;
use crate::crypto::sha256_hex;
use crate::policy::EvidenceValidationError;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DnsEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

impl DnsEndpoint {
    pub fn normalized(&self) -> Result<Self, EvidenceValidationError> {
        let transport = self.transport.trim().to_lowercase();
        let ip = self
            .ip
            .as_deref()
            .map(|value| {
                IpAddr::from_str(value.trim())
                    .map(|address| address.to_string())
                    .map_err(|_| {
                        EvidenceValidationError::InvalidEndpoint("invalid IP address".into())
                    })
            })
            .transpose()?;
        let server_name = self
            .server_name
            .as_deref()
            .map(normalize_name)
            .filter(|value| !value.is_empty());
        let uri = self.uri.as_deref().map(canonical_uri).transpose()?;
        if ip.is_none() && server_name.is_none() && uri.is_none() {
            return Err(EvidenceValidationError::InvalidEndpoint(
                "endpoint requires an IP, server name, or URI".into(),
            ));
        }
        let mut alpn = self
            .alpn
            .iter()
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        alpn.sort();
        alpn.dedup();
        Ok(Self {
            endpoint_id: self.endpoint_id.clone(),
            ip,
            port: Some(self.port.unwrap_or_else(|| default_port(&transport))),
            transport,
            uri,
            server_name,
            alpn,
        })
    }

    pub fn matches(&self, observed: &Self) -> Result<bool, EvidenceValidationError> {
        let expected = self.normalized()?;
        let observed = observed.normalized()?;
        if expected.transport != observed.transport || expected.port != observed.port {
            return Ok(false);
        }
        if expected.ip.is_some() && expected.ip != observed.ip {
            return Ok(false);
        }
        if expected.uri.is_some() && expected.uri != observed.uri {
            return Ok(false);
        }
        if expected.server_name.is_some() && expected.server_name != observed.server_name {
            return Ok(false);
        }
        if !expected.alpn.is_empty() && expected.alpn != observed.alpn {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn cache_key(&self) -> Result<String, EvidenceValidationError> {
        let normalized = self.normalized()?;
        Ok(format!(
            "{}:{}:{}:{}:{}:{}",
            normalized.ip.as_deref().unwrap_or(""),
            normalized.port.unwrap_or_default(),
            normalized.transport,
            normalized.server_name.as_deref().unwrap_or(""),
            normalized.uri.as_deref().unwrap_or(""),
            normalized.alpn.join(",")
        ))
    }

    pub fn registry_key(&self) -> Result<String, EvidenceValidationError> {
        let normalized = self.normalized()?;
        let mut value = serde_json::to_value(normalized)
            .map_err(|error| EvidenceValidationError::Serialization(error.to_string()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("endpoint_id");
        }
        Ok(sha256_hex(format!(
            "endpoint-v2:{}",
            canonical_json_text(&value)?
        )))
    }
}

fn default_transport() -> String {
    "udp".into()
}

fn default_port(transport: &str) -> u16 {
    match transport {
        "dot" | "doq" => 853,
        "doh" => 443,
        _ => 53,
    }
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_lowercase()
}

fn canonical_uri(value: &str) -> Result<String, EvidenceValidationError> {
    let mut parsed = Url::parse(value.trim())
        .map_err(|_| EvidenceValidationError::InvalidEndpoint("invalid URI".into()))?;
    parsed.set_fragment(None);
    if parsed.path().is_empty() {
        parsed.set_path("/");
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::DnsEndpoint;

    #[test]
    fn registry_key_matches_python_publisher() {
        let endpoint = DnsEndpoint {
            endpoint_id: Some("x".into()),
            ip: Some("192.0.2.53".into()),
            port: Some(53),
            transport: "udp".into(),
            uri: None,
            server_name: None,
            alpn: vec![],
        };
        assert_eq!(
            endpoint.registry_key().unwrap(),
            "0xcb7daa6caa511c0b600e4ec264a6802117080c1612b8dcb723d7a1225a498b3b"
        );
    }

    #[test]
    fn matching_requires_every_bound_identity_field() {
        let expected = DnsEndpoint {
            endpoint_id: None,
            ip: Some("192.0.2.53".into()),
            port: Some(853),
            transport: "dot".into(),
            uri: None,
            server_name: Some("resolver.example".into()),
            alpn: vec!["dot".into()],
        };
        let ip_only = DnsEndpoint {
            server_name: None,
            alpn: vec![],
            ..expected.clone()
        };
        assert!(!expected.matches(&ip_only).unwrap());

        let mut wrong_name = expected.clone();
        wrong_name.server_name = Some("other.example".into());
        assert!(!expected.matches(&wrong_name).unwrap());
        assert!(expected.matches(&expected).unwrap());
    }
}
