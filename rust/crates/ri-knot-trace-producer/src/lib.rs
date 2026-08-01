use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use ri_core::evidence::TRACE_EVENT_V2;
use ri_core::{
    DnsEndpoint, DnssecStatus, TraceEventKind, TraceEventV2, dns_cache_object_digest,
    dns_correlation_id, dns_wire_digest, sha256_hex,
};

pub const HOOK_PROTOCOL: &str = "RIK1";
pub const ADAPTER_PROTOCOL: &str = "RI-TRACE/2";
pub const MAX_HOOK_LINE_BYTES: usize = 512;
pub const MAX_DNS_WIRE_BYTES: usize = 65_535;
pub const TRACE_PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestKey {
    pub pid: u32,
    pub request_uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookKind {
    Begin,
    Send,
    Response,
    Failure,
    Finish,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookFrame {
    pub kind: HookKind,
    pub key: RequestKey,
    pub transport: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub dnssec_status: DnssecStatus,
    pub reason: String,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Attempt {
    number: u32,
    event_id: String,
    endpoint: DnsEndpoint,
    query_digest: String,
    target_correlation_id: String,
    transaction_id: u16,
    resolved: bool,
}

#[derive(Clone, Debug)]
struct RequestContext {
    trace_id: String,
    correlation_id: String,
    query_digest: String,
    sequence: u64,
    last_event_id: String,
    last_endpoint: Option<DnsEndpoint>,
    sent_upstream: bool,
    attempts: Vec<Attempt>,
}

#[derive(Clone, Debug)]
pub struct TraceMachine {
    server_id: String,
    max_contexts: usize,
    contexts: HashMap<RequestKey, RequestContext>,
}

#[derive(Debug)]
pub enum MachineOutput {
    Events(Vec<TraceEventV2>),
    Terminal(Vec<TraceEventV2>),
}

impl MachineOutput {
    pub fn events(&self) -> &[TraceEventV2] {
        match self {
            Self::Events(events) | Self::Terminal(events) => events,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

impl TraceMachine {
    pub fn new(server_id: String, max_contexts: usize) -> Result<Self, String> {
        if server_id.is_empty() || server_id.len() > 256 || max_contexts == 0 {
            return Err("Trace Producer configuration is invalid".into());
        }
        Ok(Self {
            server_id,
            max_contexts,
            contexts: HashMap::new(),
        })
    }

    pub fn active_contexts(&self) -> usize {
        self.contexts.len()
    }

    pub fn abort(&mut self, key: RequestKey) {
        self.contexts.remove(&key);
    }

    pub fn process(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        match frame.kind {
            HookKind::Begin => self.begin(frame),
            HookKind::Send => self.send(frame),
            HookKind::Response => self.response(frame),
            HookKind::Failure => self.failure(frame),
            HookKind::Finish => self.finish(frame),
        }
    }

    fn begin(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        validate_dns_wire(&frame.wire)?;
        if self.contexts.len() >= self.max_contexts {
            return Err("Trace Producer context capacity reached".into());
        }
        if self.contexts.contains_key(&frame.key) {
            return Err("Knot request context was reused before termination".into());
        }
        let trace_id = random_trace_id();
        let correlation_id = dns_correlation_id(&frame.wire).map_err(|error| error.to_string())?;
        let query_digest = dns_wire_digest(&frame.wire);
        let event_id = event_id(&trace_id, 1);
        let event = TraceEventV2 {
            schema_version: TRACE_EVENT_V2.into(),
            event_id: event_id.clone(),
            trace_id: trace_id.clone(),
            sequence: 1,
            correlation_id: correlation_id.clone(),
            parent_event_id: None,
            kind: TraceEventKind::ClientQuery,
            observer_server_id: self.server_id.clone(),
            target_server_id: None,
            target_endpoint: None,
            target_correlation_id: None,
            attempt: None,
            query_digest: query_digest.clone(),
            response_digest: None,
            cache_object_digest: None,
            observed_at: unix_time(),
            dnssec_status: frame.dnssec_status,
            ttl_expires_at: None,
            source_graph_digest: None,
            failure_reason: None,
        };
        self.contexts.insert(
            frame.key,
            RequestContext {
                trace_id,
                correlation_id,
                query_digest,
                sequence: 1,
                last_event_id: event_id,
                last_endpoint: None,
                sent_upstream: false,
                attempts: Vec::new(),
            },
        );
        Ok(MachineOutput::Events(vec![event]))
    }

    fn send(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        validate_dns_wire(&frame.wire)?;
        let endpoint = endpoint(&frame)?;
        let context = self
            .contexts
            .get_mut(&frame.key)
            .ok_or_else(|| "outbound send has no active Knot request context".to_owned())?;
        let mut events = Vec::new();
        let attempt = u32::try_from(context.attempts.len())
            .map_err(|_| "outbound attempt count overflow")?
            .checked_add(1)
            .ok_or("outbound attempt count overflow")?;
        if context.sent_upstream {
            events.push(next_event(
                &self.server_id,
                context,
                EventFields {
                    kind: TraceEventKind::UpstreamRetry,
                    endpoint: Some(endpoint.clone()),
                    attempt: Some(attempt),
                    dnssec_status: frame.dnssec_status,
                    failure_reason: Some(if frame.reason.is_empty() {
                        "retry".into()
                    } else {
                        frame.reason.clone()
                    }),
                    ..EventFields::default()
                },
            ));
            if context
                .last_endpoint
                .as_ref()
                .is_some_and(|previous| previous != &endpoint)
            {
                events.push(next_event(
                    &self.server_id,
                    context,
                    EventFields {
                        kind: TraceEventKind::TransportSwitch,
                        endpoint: Some(endpoint.clone()),
                        attempt: Some(attempt),
                        dnssec_status: frame.dnssec_status,
                        failure_reason: Some("endpoint-or-transport-changed".into()),
                        ..EventFields::default()
                    },
                ));
            }
        }
        let target_correlation_id =
            dns_correlation_id(&frame.wire).map_err(|error| error.to_string())?;
        let query_digest = dns_wire_digest(&frame.wire);
        let query_event = next_event(
            &self.server_id,
            context,
            EventFields {
                kind: TraceEventKind::UpstreamQuery,
                endpoint: Some(endpoint.clone()),
                target_correlation_id: Some(target_correlation_id.clone()),
                attempt: Some(attempt),
                dnssec_status: frame.dnssec_status,
                ..EventFields::default()
            },
        );
        let query_event_id = query_event.event_id.clone();
        events.push(TraceEventV2 {
            query_digest: query_digest.clone(),
            ..query_event
        });
        context.attempts.push(Attempt {
            number: attempt,
            event_id: query_event_id,
            endpoint: endpoint.clone(),
            query_digest,
            target_correlation_id,
            transaction_id: dns_transaction_id(&frame.wire)?,
            resolved: false,
        });
        context.last_endpoint = Some(endpoint);
        context.sent_upstream = true;
        Ok(MachineOutput::Events(events))
    }

    fn response(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        validate_dns_wire(&frame.wire)?;
        let observed_endpoint = endpoint(&frame)?;
        let response_transaction_id = dns_transaction_id(&frame.wire)?;
        let context = self
            .contexts
            .get_mut(&frame.key)
            .ok_or_else(|| "upstream response has no active Knot request context".to_owned())?;
        let index = context
            .attempts
            .iter()
            .rposition(|attempt| {
                !attempt.resolved
                    && attempt.transaction_id == response_transaction_id
                    && attempt.endpoint == observed_endpoint
            })
            .ok_or_else(|| {
                "upstream response does not match an unresolved outbound attempt".to_owned()
            })?;
        let attempt = context.attempts[index].clone();
        let event = causal_event(
            &self.server_id,
            context,
            &attempt.event_id,
            EventFields {
                kind: TraceEventKind::UpstreamResponse,
                endpoint: Some(attempt.endpoint),
                target_correlation_id: Some(attempt.target_correlation_id),
                attempt: Some(attempt.number),
                response_digest: Some(dns_wire_digest(&frame.wire)),
                dnssec_status: frame.dnssec_status,
                ..EventFields::default()
            },
        );
        let event = TraceEventV2 {
            query_digest: attempt.query_digest,
            ..event
        };
        context.attempts[index].resolved = true;
        context.last_event_id = event.event_id.clone();
        Ok(MachineOutput::Events(vec![event]))
    }

    fn failure(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        let context = self
            .contexts
            .get_mut(&frame.key)
            .ok_or_else(|| "transport failure has no active Knot request context".to_owned())?;
        let index = context
            .attempts
            .iter()
            .rposition(|attempt| !attempt.resolved)
            .ok_or_else(|| "transport failure has no unresolved outbound attempt".to_owned())?;
        let attempt = context.attempts[index].clone();
        let event = causal_event(
            &self.server_id,
            context,
            &attempt.event_id,
            EventFields {
                kind: TraceEventKind::UpstreamTimeout,
                endpoint: Some(attempt.endpoint),
                target_correlation_id: Some(attempt.target_correlation_id),
                attempt: Some(attempt.number),
                dnssec_status: frame.dnssec_status,
                failure_reason: Some(if frame.reason.is_empty() {
                    "transport-failure".into()
                } else {
                    frame.reason
                }),
                ..EventFields::default()
            },
        );
        let event = TraceEventV2 {
            query_digest: attempt.query_digest,
            ..event
        };
        context.attempts[index].resolved = true;
        context.last_event_id = event.event_id.clone();
        Ok(MachineOutput::Events(vec![event]))
    }

    fn finish(&mut self, frame: HookFrame) -> Result<MachineOutput, String> {
        validate_dns_wire(&frame.wire)?;
        let mut context = self
            .contexts
            .remove(&frame.key)
            .ok_or_else(|| "finish has no active Knot request context".to_owned())?;
        let response_digest = dns_wire_digest(&frame.wire);
        let cache_object_digest =
            dns_cache_object_digest(&frame.wire).map_err(|error| error.to_string())?;
        let mut events = Vec::new();
        if !context.sent_upstream && frame.reason == "success" {
            let ttl = minimum_dns_ttl(&frame.wire)?;
            events.push(next_event(
                &self.server_id,
                &mut context,
                EventFields {
                    kind: TraceEventKind::CacheHit,
                    response_digest: Some(response_digest.clone()),
                    dnssec_status: frame.dnssec_status,
                    ..EventFields::default()
                },
            ));
            let expires = unix_time().saturating_add(i64::from(ttl));
            if let Some(event) = events.last_mut() {
                event.ttl_expires_at = Some(expires);
                event.cache_object_digest = Some(cache_object_digest.clone());
            }
        }
        let failed = frame.reason != "success";
        events.push(next_event(
            &self.server_id,
            &mut context,
            EventFields {
                kind: if failed {
                    TraceEventKind::ResolutionFailed
                } else {
                    TraceEventKind::ClientResponse
                },
                response_digest: Some(response_digest),
                dnssec_status: frame.dnssec_status,
                failure_reason: failed.then_some(if frame.reason.is_empty() {
                    "resolver-failed".into()
                } else {
                    frame.reason
                }),
                ..EventFields::default()
            },
        ));
        if !failed && let Some(event) = events.last_mut() {
            event.cache_object_digest = Some(cache_object_digest);
        }
        Ok(MachineOutput::Terminal(events))
    }
}

struct EventFields {
    kind: TraceEventKind,
    endpoint: Option<DnsEndpoint>,
    target_correlation_id: Option<String>,
    attempt: Option<u32>,
    response_digest: Option<String>,
    dnssec_status: DnssecStatus,
    failure_reason: Option<String>,
}

impl Default for EventFields {
    fn default() -> Self {
        Self {
            kind: TraceEventKind::ClientQuery,
            endpoint: None,
            target_correlation_id: None,
            attempt: None,
            response_digest: None,
            dnssec_status: DnssecStatus::Indeterminate,
            failure_reason: None,
        }
    }
}

fn next_event(server_id: &str, context: &mut RequestContext, fields: EventFields) -> TraceEventV2 {
    let parent = context.last_event_id.clone();
    causal_event(server_id, context, &parent, fields)
}

fn causal_event(
    server_id: &str,
    context: &mut RequestContext,
    parent_event_id: &str,
    fields: EventFields,
) -> TraceEventV2 {
    let EventFields {
        kind,
        endpoint,
        target_correlation_id,
        attempt,
        response_digest,
        dnssec_status,
        failure_reason,
    } = fields;
    context.sequence = context.sequence.saturating_add(1);
    let event_id = event_id(&context.trace_id, context.sequence);
    let event = TraceEventV2 {
        schema_version: TRACE_EVENT_V2.into(),
        event_id: event_id.clone(),
        trace_id: context.trace_id.clone(),
        sequence: context.sequence,
        correlation_id: context.correlation_id.clone(),
        parent_event_id: Some(parent_event_id.into()),
        kind,
        observer_server_id: server_id.into(),
        target_server_id: None,
        target_endpoint: endpoint,
        target_correlation_id,
        attempt,
        query_digest: context.query_digest.clone(),
        response_digest,
        cache_object_digest: None,
        observed_at: unix_time(),
        dnssec_status,
        ttl_expires_at: None,
        source_graph_digest: None,
        failure_reason,
    };
    context.last_event_id = event_id;
    event
}

fn endpoint(frame: &HookFrame) -> Result<DnsEndpoint, String> {
    let address = frame
        .address
        .ok_or_else(|| "upstream hook frame has no IP address".to_owned())?;
    if frame.port == 0 {
        return Err("upstream hook frame has an invalid port".into());
    }
    let transport = match frame.transport.as_str() {
        "udp" | "tcp" => frame.transport.clone(),
        "tls" => "dot".into(),
        _ => return Err("upstream hook frame has an invalid transport".into()),
    };
    Ok(DnsEndpoint {
        endpoint_id: None,
        ip: Some(address.to_string()),
        port: Some(frame.port),
        transport,
        uri: None,
        server_name: None,
        alpn: Vec::new(),
    })
}

pub fn parse_hook_header(line: &str) -> Result<(HookFrame, usize), String> {
    if line.len() > MAX_HOOK_LINE_BYTES {
        return Err("Knot hook header exceeds the limit".into());
    }
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 11 || fields[0] != HOOK_PROTOCOL {
        return Err("Knot hook header is malformed".into());
    }
    let kind = match fields[1] {
        "BEGIN" => HookKind::Begin,
        "SEND" => HookKind::Send,
        "RESPONSE" => HookKind::Response,
        "FAILURE" => HookKind::Failure,
        "FINISH" => HookKind::Finish,
        _ => return Err("Knot hook event kind is unknown".into()),
    };
    let pid = fields[2]
        .parse::<u32>()
        .map_err(|_| "Knot hook pid is invalid")?;
    let request_uid = fields[3]
        .parse::<u32>()
        .map_err(|_| "Knot request uid is invalid")?;
    let transport = fields[4].to_owned();
    let address = match fields[5] {
        "-" => None,
        value => Some(
            value
                .parse::<IpAddr>()
                .map_err(|_| "Knot hook address is invalid")?,
        ),
    };
    let port = fields[6]
        .parse::<u16>()
        .map_err(|_| "Knot hook port is invalid")?;
    let dnssec_status = match fields[7] {
        "secure" => DnssecStatus::Secure,
        "insecure" => DnssecStatus::Insecure,
        "bogus" => DnssecStatus::Bogus,
        "indeterminate" => DnssecStatus::Indeterminate,
        "not-applicable" => DnssecStatus::NotApplicable,
        _ => return Err("Knot hook DNSSEC status is invalid".into()),
    };
    let reason = fields[8].to_owned();
    if reason.len() > 128
        || !reason
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Knot hook reason is invalid".into());
    }
    let wire_len = fields[9]
        .parse::<usize>()
        .map_err(|_| "Knot hook wire length is invalid")?;
    if fields[10] != "-" || wire_len > MAX_DNS_WIRE_BYTES {
        return Err("Knot hook frame terminator or wire length is invalid".into());
    }
    Ok((
        HookFrame {
            kind,
            key: RequestKey { pid, request_uid },
            transport,
            address,
            port,
            dnssec_status,
            reason,
            wire: Vec::new(),
        },
        wire_len,
    ))
}

fn random_trace_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("knot-{}", hex::encode(bytes))
}

fn event_id(trace_id: &str, sequence: u64) -> String {
    sha256_hex(format!("knot-trace-event-v1:{trace_id}:{sequence}"))
}

fn validate_dns_wire(wire: &[u8]) -> Result<(), String> {
    if !(12..=MAX_DNS_WIRE_BYTES).contains(&wire.len()) {
        return Err("DNS wire length is invalid".into());
    }
    Ok(())
}

fn dns_transaction_id(wire: &[u8]) -> Result<u16, String> {
    validate_dns_wire(wire)?;
    Ok(u16::from_be_bytes([wire[0], wire[1]]))
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn minimum_dns_ttl(wire: &[u8]) -> Result<u32, String> {
    validate_dns_wire(wire)?;
    let qd = usize::from(u16::from_be_bytes([wire[4], wire[5]]));
    let an = usize::from(u16::from_be_bytes([wire[6], wire[7]]));
    let ns = usize::from(u16::from_be_bytes([wire[8], wire[9]]));
    let ar = usize::from(u16::from_be_bytes([wire[10], wire[11]]));
    let mut offset = 12;
    for _ in 0..qd {
        offset = skip_name(wire, offset)?;
        offset = offset
            .checked_add(4)
            .ok_or("DNS question length overflow")?;
        if offset > wire.len() {
            return Err("DNS question exceeds packet".into());
        }
    }
    let mut minimum = None;
    for _ in 0..an.saturating_add(ns).saturating_add(ar) {
        offset = skip_name(wire, offset)?;
        if offset.checked_add(10).is_none_or(|end| end > wire.len()) {
            return Err("DNS resource record header exceeds packet".into());
        }
        let rr_type = u16::from_be_bytes([wire[offset], wire[offset + 1]]);
        let ttl = u32::from_be_bytes([
            wire[offset + 4],
            wire[offset + 5],
            wire[offset + 6],
            wire[offset + 7],
        ]);
        let rdlength = usize::from(u16::from_be_bytes([wire[offset + 8], wire[offset + 9]]));
        offset = offset
            .checked_add(10)
            .and_then(|value| value.checked_add(rdlength))
            .ok_or("DNS resource record length overflow")?;
        if offset > wire.len() {
            return Err("DNS resource record exceeds packet".into());
        }
        if rr_type != 41 {
            minimum = Some(minimum.map_or(ttl, |current: u32| current.min(ttl)));
        }
    }
    Ok(minimum.unwrap_or(0))
}

fn skip_name(wire: &[u8], mut offset: usize) -> Result<usize, String> {
    let mut labels = 0_u16;
    loop {
        let length = *wire
            .get(offset)
            .ok_or_else(|| "DNS name exceeds packet".to_owned())?;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 == 0xc0 {
            if wire.get(offset).is_none() {
                return Err("DNS compression pointer exceeds packet".into());
            }
            return Ok(offset + 1);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err("DNS label length is invalid".into());
        }
        offset = offset
            .checked_add(usize::from(length))
            .ok_or("DNS name length overflow")?;
        if offset > wire.len() {
            return Err("DNS label exceeds packet".into());
        }
        labels = labels.saturating_add(1);
        if labels > 127 {
            return Err("DNS name contains too many labels".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16) -> Vec<u8> {
        let mut wire = vec![
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        wire[0..2].copy_from_slice(&id.to_be_bytes());
        wire
    }

    fn response(id: u16, ttl: u32) -> Vec<u8> {
        let mut wire = query(id);
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[6] = 0;
        wire[7] = 1;
        wire.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        wire
    }

    fn frame(kind: HookKind, wire: Vec<u8>) -> HookFrame {
        HookFrame {
            kind,
            key: RequestKey {
                pid: 10,
                request_uid: 20,
            },
            transport: "udp".into(),
            address: Some("192.0.2.53".parse().unwrap()),
            port: 53,
            dnssec_status: DnssecStatus::Secure,
            reason: "success".into(),
            wire,
        }
    }

    #[test]
    fn exact_context_survives_same_qname_and_transaction_id() {
        let mut machine = TraceMachine::new("operator/L01/r1".into(), 10).unwrap();
        let first = frame(HookKind::Begin, query(7));
        let mut second = first.clone();
        second.key.request_uid = 21;
        let first_id = machine.process(first).unwrap().events()[0].trace_id.clone();
        let second_id = machine.process(second).unwrap().events()[0]
            .trace_id
            .clone();
        assert_ne!(first_id, second_id);
        assert_eq!(machine.active_contexts(), 2);
    }

    #[test]
    fn response_requires_exact_attempt_and_causal_parent() {
        let mut machine = TraceMachine::new("operator/L01/r1".into(), 10).unwrap();
        machine.process(frame(HookKind::Begin, query(7))).unwrap();
        let send = machine
            .process(frame(HookKind::Send, query(42)))
            .unwrap()
            .events()[0]
            .clone();
        let received = machine
            .process(frame(HookKind::Response, response(42, 60)))
            .unwrap()
            .events()[0]
            .clone();
        assert_eq!(
            received.parent_event_id.as_deref(),
            Some(send.event_id.as_str())
        );
        assert_eq!(received.attempt, Some(1));

        let error = machine
            .process(frame(HookKind::Response, response(99, 60)))
            .unwrap_err();
        assert!(error.contains("unresolved outbound attempt"));
    }

    #[test]
    fn retry_and_transport_switch_are_explicit() {
        let mut machine = TraceMachine::new("operator/L01/r1".into(), 10).unwrap();
        machine.process(frame(HookKind::Begin, query(7))).unwrap();
        machine.process(frame(HookKind::Send, query(40))).unwrap();
        let mut failed = frame(HookKind::Failure, Vec::new());
        failed.reason = "timeout".into();
        machine.process(failed).unwrap();
        let mut retry = frame(HookKind::Send, query(41));
        retry.transport = "tcp".into();
        let events = machine.process(retry).unwrap();
        assert_eq!(
            events
                .events()
                .iter()
                .map(|event| event.kind)
                .collect::<Vec<_>>(),
            [
                TraceEventKind::UpstreamRetry,
                TraceEventKind::TransportSwitch,
                TraceEventKind::UpstreamQuery
            ]
        );
    }

    #[test]
    fn cache_hit_has_exact_ttl_and_terminal_response() {
        let mut machine = TraceMachine::new("operator/L01/r1".into(), 10).unwrap();
        machine.process(frame(HookKind::Begin, query(7))).unwrap();
        let events = machine
            .process(frame(HookKind::Finish, response(7, 45)))
            .unwrap();
        assert!(events.is_terminal());
        assert_eq!(events.events()[0].kind, TraceEventKind::CacheHit);
        assert_eq!(
            events.events()[0].ttl_expires_at,
            Some(unix_time().saturating_add(45))
        );
        assert_eq!(events.events()[1].kind, TraceEventKind::ClientResponse);
    }

    #[test]
    fn header_parser_rejects_unknown_or_oversized_input() {
        assert!(parse_hook_header("RIK1 WAT 1 2 udp - 0 secure x 0 -").is_err());
        assert!(parse_hook_header(&"x".repeat(MAX_HOOK_LINE_BYTES + 1)).is_err());
    }
}
