use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::crypto::{object_hash, verify_ed25519};
use crate::evidence::{
    DNS_SERVER_IDENTITY_V2, DnssecStatus, EvidenceLevel, QUERY_EVIDENCE_GRAPH_V2,
    QueryEvidenceGraphV2, SERVER_HOP_EVIDENCE_V2, TARGET_RESPONSE_ATTESTATION_V2, VerificationMode,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EvidenceValidationError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("missing signature")]
    MissingSignature,
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    #[error("identity is not active: {0}")]
    IdentityNotActive(String),
    #[error("identity issuer key not found: {0}/{1}")]
    IssuerKeyNotFound(String, String),
    #[error("invalid graph: {0}")]
    InvalidGraph(String),
    #[error("policy rejected evidence: {0}")]
    PolicyRejected(String),
}

#[derive(Clone, Debug)]
pub struct EvidencePolicy {
    pub mode: VerificationMode,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_depth: usize,
    pub max_clock_skew_seconds: i64,
    pub max_observation_age_seconds: i64,
    pub max_evidence_ttl_seconds: i64,
    pub require_dnssec_for_authorities: bool,
    pub require_target_attestation: bool,
}

impl EvidencePolicy {
    pub fn controlled_strict() -> Self {
        Self {
            mode: VerificationMode::ControlledStrict,
            max_nodes: 64,
            max_edges: 128,
            max_depth: 32,
            max_clock_skew_seconds: 5,
            max_observation_age_seconds: 300,
            max_evidence_ttl_seconds: 60,
            require_dnssec_for_authorities: true,
            require_target_attestation: true,
        }
    }

    pub fn public_hybrid() -> Self {
        Self {
            mode: VerificationMode::PublicHybrid,
            max_nodes: 128,
            max_edges: 256,
            max_depth: 64,
            max_clock_skew_seconds: 5,
            max_observation_age_seconds: 300,
            max_evidence_ttl_seconds: 60,
            require_dnssec_for_authorities: true,
            require_target_attestation: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IssuerKeyRegistry {
    keys: HashMap<(String, String), String>,
}

impl IssuerKeyRegistry {
    pub fn insert(
        &mut self,
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        public_key_b64: impl Into<String>,
    ) {
        self.keys
            .insert((issuer.into(), key_id.into()), public_key_b64.into());
    }

    pub fn get(&self, issuer: &str, key_id: &str) -> Option<&str> {
        self.keys
            .get(&(issuer.to_owned(), key_id.to_owned()))
            .map(String::as_str)
    }
}

pub struct EvidenceValidator<'a> {
    pub policy: &'a EvidencePolicy,
    pub issuer_keys: &'a IssuerKeyRegistry,
}

type RegistryAnchor<'a> = (
    &'a str,
    &'a str,
    &'a str,
    Option<u64>,
    Option<&'a str>,
    Option<&'a str>,
);

impl EvidenceValidator<'_> {
    pub fn validate_graph(
        &self,
        graph: &QueryEvidenceGraphV2,
        expected_challenge: &str,
        now: i64,
    ) -> Result<(), EvidenceValidationError> {
        if graph.schema_version != QUERY_EVIDENCE_GRAPH_V2 {
            return Err(EvidenceValidationError::UnsupportedSchema(
                graph.schema_version.clone(),
            ));
        }
        if graph.mode != self.policy.mode {
            return Err(EvidenceValidationError::PolicyRejected(
                "verification mode mismatch".into(),
            ));
        }
        if graph.challenge != expected_challenge {
            return Err(EvidenceValidationError::InvalidGraph(
                "challenge mismatch".into(),
            ));
        }
        if graph.trace_id.is_empty()
            || graph.trace_id.len() > 256
            || !(32..=256).contains(&graph.challenge.len())
            || graph.key_id.is_empty()
        {
            return Err(EvidenceValidationError::InvalidGraph(
                "graph identifiers are invalid".into(),
            ));
        }
        if !is_bytes32_hex(&graph.correlation_id)
            || !is_bytes32_hex(&graph.query_digest)
            || !is_bytes32_hex(&graph.response_digest)
        {
            return Err(EvidenceValidationError::InvalidGraph(
                "graph DNS/correlation digest is invalid".into(),
            ));
        }
        validate_window(
            graph.issued_at,
            graph.expires_at,
            now,
            self.policy.max_clock_skew_seconds,
        )?;
        validate_evidence_ttl(
            graph.issued_at,
            graph.expires_at,
            self.policy.max_evidence_ttl_seconds,
        )?;
        if graph.nodes.is_empty() || graph.nodes.len() > self.policy.max_nodes {
            return Err(EvidenceValidationError::InvalidGraph(
                "node count outside policy".into(),
            ));
        }
        if graph.edges.len() > self.policy.max_edges {
            return Err(EvidenceValidationError::InvalidGraph(
                "edge count outside policy".into(),
            ));
        }
        if !graph.final_result || !graph.graph_errors.is_empty() {
            return Err(EvidenceValidationError::PolicyRejected(
                "graph reports a failed result".into(),
            ));
        }

        let mut nodes = HashMap::new();
        let mut registry_anchor: Option<RegistryAnchor<'_>> = None;
        for node in &graph.nodes {
            let identity = &node.identity;
            if identity.schema_version != DNS_SERVER_IDENTITY_V2 {
                return Err(EvidenceValidationError::UnsupportedSchema(
                    identity.schema_version.clone(),
                ));
            }
            validate_identity_shape(identity)?;
            validate_registry_shape(&node.registry)?;
            let anchor = (
                node.registry.chain_identity.as_str(),
                node.registry.registry_locator.as_str(),
                node.registry.registry_schema_hash.as_str(),
                node.registry.evm_chain_id,
                node.registry.evm_contract_address.as_deref(),
                node.registry.evm_runtime_code_hash.as_deref(),
            );
            if registry_anchor.is_some_and(|expected| expected != anchor) {
                return Err(EvidenceValidationError::InvalidGraph(
                    "nodes reference different Registry deployments".into(),
                ));
            }
            registry_anchor = Some(anchor);
            if nodes.insert(identity.server_id.as_str(), node).is_some() {
                return Err(EvidenceValidationError::InvalidGraph(
                    "duplicate server_id".into(),
                ));
            }
            if !node.accepted || !node.reasons.is_empty() || !identity.active_at(now) {
                return Err(EvidenceValidationError::IdentityNotActive(
                    identity.server_id.clone(),
                ));
            }
            let issuer_key = self
                .issuer_keys
                .get(&identity.issuer, &identity.key_id)
                .ok_or_else(|| {
                    EvidenceValidationError::IssuerKeyNotFound(
                        identity.issuer.clone(),
                        identity.key_id.clone(),
                    )
                })?;
            verify_ed25519(identity, issuer_key)?;
            self.validate_node_policy(node)?;
            if node.registry.object_hash != object_hash(identity)?
                || node.registry.object_version != identity.object_version
                || node.registry.resolver_status != "ACTIVE"
                || node.registry.root_status != "ACTIVE"
                || node.registry.endpoint_binding_status != "MATCHED"
            {
                return Err(EvidenceValidationError::InvalidGraph(format!(
                    "registry evidence mismatch for {}",
                    identity.server_id
                )));
            }
        }

        let entry = nodes
            .get(graph.entry_server_id.as_str())
            .ok_or_else(|| EvidenceValidationError::InvalidGraph("entry server missing".into()))?;
        let entry_agent_key = entry.identity.agent.as_ref().ok_or_else(|| {
            EvidenceValidationError::PolicyRejected("entry server does not bind an Agent".into())
        })?;
        if graph.key_id != entry_agent_key.key_id
            || !entry_agent_key.algorithm.eq_ignore_ascii_case("ed25519")
        {
            return Err(EvidenceValidationError::PolicyRejected(
                "graph Agent key binding mismatch".into(),
            ));
        }
        let entry_agent_key = entry_agent_key.public_key.as_str();
        verify_ed25519(graph, entry_agent_key)?;

        let mut edge_ids = HashSet::new();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &graph.edges {
            if edge.schema_version != SERVER_HOP_EVIDENCE_V2 {
                return Err(EvidenceValidationError::UnsupportedSchema(
                    edge.schema_version.clone(),
                ));
            }
            if !edge_ids.insert(edge.edge_id.as_str()) {
                return Err(EvidenceValidationError::InvalidGraph(
                    "duplicate edge_id".into(),
                ));
            }
            if edge.trace_id != graph.trace_id || edge.challenge != graph.challenge {
                return Err(EvidenceValidationError::InvalidGraph(
                    "edge binding mismatch".into(),
                ));
            }
            if !is_bytes32_hex(&edge.target_correlation_id)
                || !is_bytes32_hex(&edge.query_digest)
                || !is_bytes32_hex(&edge.response_digest)
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "edge DNS/correlation digest is invalid".into(),
                ));
            }
            validate_window(
                edge.issued_at,
                edge.expires_at,
                now,
                self.policy.max_clock_skew_seconds,
            )?;
            validate_evidence_ttl(
                edge.issued_at,
                edge.expires_at,
                self.policy.max_evidence_ttl_seconds,
            )?;
            validate_observation(
                edge.observed_at,
                now,
                self.policy.max_clock_skew_seconds,
                self.policy.max_observation_age_seconds,
            )?;
            if !edge.accepted || !edge.reasons.is_empty() {
                return Err(EvidenceValidationError::PolicyRejected(format!(
                    "edge {} was rejected",
                    edge.edge_id
                )));
            }
            let from = nodes.get(edge.from_server_id.as_str()).ok_or_else(|| {
                EvidenceValidationError::InvalidGraph("edge source missing".into())
            })?;
            let to = nodes.get(edge.to_server_id.as_str()).ok_or_else(|| {
                EvidenceValidationError::InvalidGraph("edge target missing".into())
            })?;
            if edge.registry != to.registry {
                return Err(EvidenceValidationError::InvalidGraph(format!(
                    "edge {} Registry reference differs from target node",
                    edge.edge_id
                )));
            }
            if edge.from_server_id == edge.to_server_id {
                return Err(EvidenceValidationError::InvalidGraph(
                    "self edge is forbidden".into(),
                ));
            }
            if !from
                .identity
                .endpoints
                .iter()
                .any(|endpoint| endpoint.matches(&edge.from_endpoint).unwrap_or(false))
                || !to
                    .identity
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.matches(&edge.to_endpoint).unwrap_or(false))
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "edge endpoint is not bound to identity".into(),
                ));
            }
            let from_agent_key = from.identity.agent.as_ref().ok_or_else(|| {
                EvidenceValidationError::PolicyRejected(format!(
                    "edge source {} does not bind an Agent",
                    edge.from_server_id
                ))
            })?;
            if edge.key_id != from_agent_key.key_id
                || !from_agent_key.algorithm.eq_ignore_ascii_case("ed25519")
            {
                return Err(EvidenceValidationError::PolicyRejected(format!(
                    "edge {} Agent key binding mismatch",
                    edge.edge_id
                )));
            }
            let from_agent_key = from_agent_key.public_key.as_str();
            verify_ed25519(edge, from_agent_key)?;
            if let Some(attestation) = &edge.target_attestation {
                if attestation.schema_version != TARGET_RESPONSE_ATTESTATION_V2
                    || attestation.target_server_id != edge.to_server_id
                    || attestation.trace_id != edge.trace_id
                    || attestation.correlation_id != edge.target_correlation_id
                    || attestation.challenge != edge.challenge
                    || attestation.query_digest != edge.query_digest
                    || attestation.response_digest != edge.response_digest
                    || !attestation.endpoint.matches(&edge.to_endpoint)?
                {
                    return Err(EvidenceValidationError::InvalidGraph(
                        "target attestation binding mismatch".into(),
                    ));
                }
                let target_agent_key = to.identity.agent.as_ref().ok_or_else(|| {
                    EvidenceValidationError::PolicyRejected(
                        "target attestation has no bound Agent key".into(),
                    )
                })?;
                validate_window(
                    attestation.issued_at,
                    attestation.expires_at,
                    now,
                    self.policy.max_clock_skew_seconds,
                )?;
                validate_evidence_ttl(
                    attestation.issued_at,
                    attestation.expires_at,
                    self.policy.max_evidence_ttl_seconds,
                )?;
                validate_observation(
                    attestation.observed_at,
                    now,
                    self.policy.max_clock_skew_seconds,
                    self.policy.max_observation_age_seconds,
                )?;
                if attestation.key_id != target_agent_key.key_id
                    || !target_agent_key.algorithm.eq_ignore_ascii_case("ed25519")
                {
                    return Err(EvidenceValidationError::PolicyRejected(
                        "target attestation Agent key binding mismatch".into(),
                    ));
                }
                let target_agent_key = target_agent_key.public_key.as_str();
                verify_ed25519(attestation, target_agent_key)?;
            } else if self.policy.require_target_attestation {
                return Err(EvidenceValidationError::PolicyRejected(format!(
                    "edge {} lacks target response attestation",
                    edge.edge_id
                )));
            }
            adjacency
                .entry(edge.from_server_id.as_str())
                .or_default()
                .push(edge.to_server_id.as_str());
        }

        self.validate_topology(graph, &nodes, &adjacency)?;
        self.validate_cache_provenance(graph, now)?;
        self.validate_terminal_cache_graphs(graph, &nodes, now)?;
        self.validate_dnssec_summary(graph, &nodes)?;
        Ok(())
    }

    fn validate_node_policy(
        &self,
        node: &crate::evidence::EvidenceNodeV2,
    ) -> Result<(), EvidenceValidationError> {
        let levels = &node.evidence_levels;
        if !levels.contains(&EvidenceLevel::RegistryBound) {
            return Err(EvidenceValidationError::PolicyRejected(format!(
                "{} lacks registry binding",
                node.identity.server_id
            )));
        }
        match self.policy.mode {
            VerificationMode::ControlledStrict => {
                if !levels.contains(&EvidenceLevel::AgentAttested) || node.identity.agent.is_none()
                {
                    return Err(EvidenceValidationError::PolicyRejected(format!(
                        "{} is not Agent-attested",
                        node.identity.server_id
                    )));
                }
            }
            VerificationMode::PublicHybrid => {
                if node.identity.role.is_authority() {
                    if self.policy.require_dnssec_for_authorities
                        && !levels.contains(&EvidenceLevel::DnssecValidated)
                        && !levels.contains(&EvidenceLevel::AgentAttested)
                    {
                        return Err(EvidenceValidationError::PolicyRejected(format!(
                            "{} lacks DNSSEC or Agent evidence",
                            node.identity.server_id
                        )));
                    }
                } else if !levels.contains(&EvidenceLevel::AgentAttested)
                    || node.identity.agent.is_none()
                {
                    return Err(EvidenceValidationError::PolicyRejected(format!(
                        "{} is a recursive/forwarding server without Agent evidence",
                        node.identity.server_id
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_topology<'a>(
        &self,
        graph: &QueryEvidenceGraphV2,
        nodes: &HashMap<&'a str, &'a crate::evidence::EvidenceNodeV2>,
        adjacency: &HashMap<&'a str, Vec<&'a str>>,
    ) -> Result<(), EvidenceValidationError> {
        let mut depth = HashMap::new();
        let mut queue = VecDeque::from([(graph.entry_server_id.as_str(), 0usize)]);
        while let Some((server_id, current_depth)) = queue.pop_front() {
            if current_depth > self.policy.max_depth {
                return Err(EvidenceValidationError::InvalidGraph(
                    "graph exceeds maximum depth".into(),
                ));
            }
            if depth
                .get(server_id)
                .is_some_and(|seen| *seen <= current_depth)
            {
                continue;
            }
            depth.insert(server_id, current_depth);
            for target in adjacency.get(server_id).into_iter().flatten() {
                queue.push_back((target, current_depth + 1));
            }
        }
        if depth.len() != nodes.len() {
            return Err(EvidenceValidationError::InvalidGraph(
                "graph contains unreachable nodes or a detached cycle".into(),
            ));
        }

        detect_cycle(
            graph.entry_server_id.as_str(),
            adjacency,
            &mut HashSet::new(),
            &mut HashSet::new(),
        )?;

        let terminal_ids = graph
            .terminal_node_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if terminal_ids.len() != graph.terminal_node_ids.len() {
            return Err(EvidenceValidationError::InvalidGraph(
                "terminal node list contains duplicates".into(),
            ));
        }
        if terminal_ids.is_empty() {
            return Err(EvidenceValidationError::InvalidGraph(
                "graph has no terminal node".into(),
            ));
        }
        for terminal in &terminal_ids {
            if !nodes.contains_key(terminal)
                || adjacency
                    .get(terminal)
                    .is_some_and(|edges| !edges.is_empty())
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "invalid terminal node".into(),
                ));
            }
        }
        for server_id in nodes.keys() {
            if !adjacency.contains_key(server_id) && !terminal_ids.contains(server_id) {
                return Err(EvidenceValidationError::InvalidGraph(
                    "leaf node is not declared terminal".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_cache_provenance(
        &self,
        graph: &QueryEvidenceGraphV2,
        now: i64,
    ) -> Result<(), EvidenceValidationError> {
        if let Some(provenance) = &graph.cache_provenance {
            if provenance.dns_ttl_expires_at < now || provenance.identity_expires_at < now {
                return Err(EvidenceValidationError::PolicyRejected(
                    "cache provenance expired".into(),
                ));
            }
            if !is_bytes32_hex(&provenance.source_graph_digest)
                || provenance.cached_at > now + self.policy.max_clock_skew_seconds
                || provenance.cached_at > provenance.dns_ttl_expires_at
            {
                return Err(EvidenceValidationError::PolicyRejected(
                    "cache provenance is invalid".into(),
                ));
            }
            if !graph.edges.is_empty()
                || graph.nodes.len() != 1
                || graph.terminal_node_ids.len() != 1
                || graph.terminal_node_ids.first() != Some(&graph.entry_server_id)
            {
                return Err(EvidenceValidationError::PolicyRejected(
                    "cache graph must contain only the entry node".into(),
                ));
            }
            let max_generation = graph
                .nodes
                .iter()
                .map(|node| node.registry.snapshot_generation)
                .max()
                .unwrap_or_default();
            if provenance.snapshot_generation != max_generation {
                return Err(EvidenceValidationError::PolicyRejected(
                    "cache provenance generation mismatch".into(),
                ));
            }
        } else if graph.edges.is_empty() {
            return Err(EvidenceValidationError::PolicyRejected(
                "edge-less graph requires cache provenance".into(),
            ));
        }
        Ok(())
    }

    fn validate_terminal_cache_graphs<'a>(
        &self,
        graph: &QueryEvidenceGraphV2,
        nodes: &HashMap<&'a str, &'a crate::evidence::EvidenceNodeV2>,
        now: i64,
    ) -> Result<(), EvidenceValidationError> {
        if graph.cache_provenance.is_some() {
            if !graph.terminal_cache_graphs.is_empty() {
                return Err(EvidenceValidationError::InvalidGraph(
                    "a cache graph cannot contain nested cache graphs".into(),
                ));
            }
            return Ok(());
        }
        if graph.terminal_cache_graphs.len() > self.policy.max_edges {
            return Err(EvidenceValidationError::InvalidGraph(
                "too many terminal cache graphs".into(),
            ));
        }

        let terminal_ids = graph
            .terminal_node_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let expected = graph
            .edges
            .iter()
            .filter(|edge| {
                terminal_ids.contains(edge.to_server_id.as_str())
                    && nodes
                        .get(edge.to_server_id.as_str())
                        .is_some_and(|node| node.identity.role.is_recursive())
            })
            .map(|edge| {
                (
                    edge.to_server_id.clone(),
                    edge.target_correlation_id.clone(),
                    edge.query_digest.clone(),
                    edge.response_digest.clone(),
                )
            })
            .collect::<HashSet<_>>();
        let mut supplied = HashSet::new();

        for child in &graph.terminal_cache_graphs {
            if child.cache_provenance.is_none()
                || !child.edges.is_empty()
                || !child.terminal_cache_graphs.is_empty()
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "terminal cache attachment is not an edge-less cache graph".into(),
                ));
            }
            if child.trace_id != graph.trace_id
                || child.challenge != graph.challenge
                || child.mode != graph.mode
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "terminal cache graph request binding mismatch".into(),
                ));
            }
            let parent_node = nodes.get(child.entry_server_id.as_str()).ok_or_else(|| {
                EvidenceValidationError::InvalidGraph(
                    "terminal cache graph entry is not in the parent graph".into(),
                )
            })?;
            if !terminal_ids.contains(child.entry_server_id.as_str())
                || !parent_node.identity.role.is_recursive()
                || child.nodes.len() != 1
                || child.nodes.first().is_none_or(|child_node| {
                    child_node.identity != parent_node.identity
                        || !same_registry_semantics(&child_node.registry, &parent_node.registry)
                })
            {
                return Err(EvidenceValidationError::InvalidGraph(
                    "terminal cache graph identity binding mismatch".into(),
                ));
            }
            let key = (
                child.entry_server_id.clone(),
                child.correlation_id.clone(),
                child.query_digest.clone(),
                child.response_digest.clone(),
            );
            if !expected.contains(&key) || !supplied.insert(key) {
                return Err(EvidenceValidationError::InvalidGraph(
                    "terminal cache graph has no unique matching parent edge".into(),
                ));
            }
            self.validate_graph(child, &graph.challenge, now)?;
        }

        if supplied != expected {
            return Err(EvidenceValidationError::PolicyRejected(
                "recursive terminal lacks signed cache provenance".into(),
            ));
        }
        Ok(())
    }

    fn validate_dnssec_summary(
        &self,
        graph: &QueryEvidenceGraphV2,
        nodes: &HashMap<&str, &crate::evidence::EvidenceNodeV2>,
    ) -> Result<(), EvidenceValidationError> {
        let direct_authority = nodes.values().any(|node| node.identity.role.is_authority());
        let cached_authority = graph
            .cache_provenance
            .as_ref()
            .is_some_and(|provenance| provenance.source_dnssec_required)
            || graph
                .terminal_cache_graphs
                .iter()
                .any(graph_requires_dnssec);
        let expected = if !direct_authority && !cached_authority {
            DnssecStatus::NotApplicable
        } else {
            let direct_secure = graph.edges.iter().all(|edge| {
                nodes
                    .get(edge.to_server_id.as_str())
                    .is_none_or(|node| !node.identity.role.is_authority())
                    || nodes.get(edge.to_server_id.as_str()).is_some_and(|node| {
                        node.evidence_levels
                            .contains(&EvidenceLevel::DnssecValidated)
                    })
            });
            let cached_secure = graph
                .terminal_cache_graphs
                .iter()
                .filter(|child| graph_requires_dnssec(child))
                .all(|child| child.dnssec_status == DnssecStatus::Secure);
            if direct_secure && cached_secure {
                DnssecStatus::Secure
            } else {
                DnssecStatus::Indeterminate
            }
        };
        if graph.dnssec_status != expected {
            return Err(EvidenceValidationError::InvalidGraph(
                "graph DNSSEC summary does not match its direct and cached paths".into(),
            ));
        }
        if self.policy.require_dnssec_for_authorities
            && (direct_authority || cached_authority)
            && expected != DnssecStatus::Secure
        {
            return Err(EvidenceValidationError::PolicyRejected(
                "authority path is not DNSSEC secure".into(),
            ));
        }
        Ok(())
    }
}

fn graph_requires_dnssec(graph: &QueryEvidenceGraphV2) -> bool {
    graph
        .nodes
        .iter()
        .any(|node| node.identity.role.is_authority())
        || graph
            .cache_provenance
            .as_ref()
            .is_some_and(|provenance| provenance.source_dnssec_required)
        || graph
            .terminal_cache_graphs
            .iter()
            .any(graph_requires_dnssec)
}

fn same_registry_semantics(
    left: &crate::evidence::RegistryReferenceV2,
    right: &crate::evidence::RegistryReferenceV2,
) -> bool {
    left.chain_adapter == right.chain_adapter
        && left.chain_identity == right.chain_identity
        && left.registry_locator == right.registry_locator
        && left.registry_schema_hash == right.registry_schema_hash
        && left.evm_chain_id == right.evm_chain_id
        && left.evm_contract_address == right.evm_contract_address
        && left.evm_runtime_code_hash == right.evm_runtime_code_hash
        && left.state_root == right.state_root
        && left.object_hash == right.object_hash
        && left.object_version == right.object_version
        && left.resolver_status == right.resolver_status
        && left.root_status == right.root_status
        && left.endpoint_binding_status == right.endpoint_binding_status
}

fn validate_window(
    issued_at: i64,
    expires_at: i64,
    now: i64,
    max_clock_skew_seconds: i64,
) -> Result<(), EvidenceValidationError> {
    if issued_at > now + max_clock_skew_seconds {
        return Err(EvidenceValidationError::PolicyRejected(
            "evidence issued in the future".into(),
        ));
    }
    if expires_at < now {
        return Err(EvidenceValidationError::PolicyRejected(
            "evidence expired".into(),
        ));
    }
    Ok(())
}

fn validate_evidence_ttl(
    issued_at: i64,
    expires_at: i64,
    max_ttl_seconds: i64,
) -> Result<(), EvidenceValidationError> {
    if expires_at < issued_at || expires_at - issued_at > max_ttl_seconds {
        return Err(EvidenceValidationError::PolicyRejected(
            "evidence validity duration exceeds policy".into(),
        ));
    }
    Ok(())
}

fn validate_observation(
    observed_at: i64,
    now: i64,
    max_clock_skew_seconds: i64,
    max_age_seconds: i64,
) -> Result<(), EvidenceValidationError> {
    if observed_at > now + max_clock_skew_seconds || observed_at < now - max_age_seconds {
        return Err(EvidenceValidationError::PolicyRejected(
            "evidence observation time is outside policy".into(),
        ));
    }
    Ok(())
}

fn validate_identity_shape(
    identity: &crate::evidence::DnsServerIdentityV2,
) -> Result<(), EvidenceValidationError> {
    if identity.server_id.is_empty()
        || identity.server_id.len() > 256
        || identity.operator_id.is_empty()
        || identity.issuer.is_empty()
        || identity.key_id.is_empty()
        || identity.object_version == 0
        || identity.valid_from >= identity.valid_until
        || identity.endpoints.is_empty()
        || identity.endpoints.len() > 32
        || identity.anycast != identity.anycast_service_id.is_some()
    {
        return Err(EvidenceValidationError::InvalidGraph(format!(
            "identity {} has invalid required fields",
            identity.server_id
        )));
    }
    let mut endpoint_keys = HashSet::new();
    for endpoint in &identity.endpoints {
        let key = endpoint.cache_key()?;
        if !endpoint_keys.insert(key) {
            return Err(EvidenceValidationError::InvalidGraph(format!(
                "identity {} contains duplicate endpoints",
                identity.server_id
            )));
        }
    }
    if let Some(agent) = &identity.agent
        && (agent.key_id.is_empty()
            || !agent.algorithm.eq_ignore_ascii_case("ed25519")
            || agent.public_key.is_empty()
            || agent.service_url.as_deref().is_none_or(str::is_empty))
    {
        return Err(EvidenceValidationError::InvalidGraph(format!(
            "identity {} has an invalid Agent binding",
            identity.server_id
        )));
    }
    Ok(())
}

fn validate_registry_shape(
    registry: &crate::evidence::RegistryReferenceV2,
) -> Result<(), EvidenceValidationError> {
    let explicit_multichain_fields = !registry.chain_identity.is_empty()
        && !registry.registry_locator.is_empty()
        && is_bytes32_hex(&registry.registry_schema_hash);
    let evm_fields_valid = if registry.chain_adapter == "evm" {
        registry.evm_chain_id.is_some_and(|value| value > 0)
            && registry
                .evm_contract_address
                .as_deref()
                .is_some_and(|value| is_hex_width(value, 20))
            && registry
                .evm_runtime_code_hash
                .as_deref()
                .is_some_and(is_bytes32_hex)
    } else {
        registry.evm_chain_id.is_none()
            && registry.evm_contract_address.is_none()
            && registry.evm_runtime_code_hash.is_none()
    };
    if registry.chain_adapter.is_empty()
        || registry.chain_adapter.len() > 32
        || !registry
            .chain_adapter
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !explicit_multichain_fields
        || !evm_fields_valid
        || registry.finalized_block == 0
        || !is_bytes32_hex(&registry.finalized_block_hash)
        || !is_bytes32_hex(&registry.state_root)
        || !is_bytes32_hex(&registry.object_hash)
    {
        return Err(EvidenceValidationError::InvalidGraph(
            "Registry reference fields are invalid".into(),
        ));
    }
    Ok(())
}

fn detect_cycle<'a>(
    node: &'a str,
    adjacency: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
) -> Result<(), EvidenceValidationError> {
    if visiting.contains(node) {
        return Err(EvidenceValidationError::InvalidGraph(
            "graph contains a cycle".into(),
        ));
    }
    if visited.contains(node) {
        return Ok(());
    }
    visiting.insert(node);
    for target in adjacency.get(node).into_iter().flatten() {
        detect_cycle(target, adjacency, visiting, visited)?;
    }
    visiting.remove(node);
    visited.insert(node);
    Ok(())
}

fn is_bytes32_hex(value: &str) -> bool {
    is_hex_width(value, 32)
}

fn is_hex_width(value: &str, bytes: usize) -> bool {
    value.len() == 2 + bytes * 2
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
