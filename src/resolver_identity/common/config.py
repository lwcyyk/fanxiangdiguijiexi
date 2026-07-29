from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.common.agent_transport import validate_agent_url_config


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _env_float(name: str, default: float) -> float:
    return float(_env(name, str(default)))


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _secret(name: str, default: str = "") -> str:
    file_name = _env(f"{name}_FILE")
    if file_name:
        return Path(file_name).read_text(encoding="utf-8").strip()
    return _env(name, default)


@dataclass(slots=True)
class Settings:
    environment: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_ENVIRONMENT", "development"))
    db_path: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_DB", "./resolver_identity.db"))
    signature_secret: str = field(default_factory=lambda: _secret("RESOLVER_IDENTITY_SIGNATURE_SECRET", "prototype-secret"))
    allow_hmac_object_signatures: bool = field(default_factory=lambda: _env_bool("RESOLVER_IDENTITY_ALLOW_HMAC_OBJECT_SIGNATURES", True))
    issuer_keys_file: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_ISSUER_KEYS_FILE", ""))
    issuer_private_key_b64: str = field(default_factory=lambda: _secret("RESOLVER_IDENTITY_ISSUER_PRIVATE_KEY_B64", ""))
    admin_api_token: str = field(default_factory=lambda: _secret("RESOLVER_IDENTITY_ADMIN_API_TOKEN", ""))

    upstream_ip: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_UPSTREAM_IP", "1.1.1.1"))
    upstream_port: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_UPSTREAM_PORT", 53))
    upstream_transport: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_UPSTREAM_TRANSPORT", "udp"))
    fallback_upstreams: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_FALLBACK_UPSTREAMS", ""))
    soft_ttl_seconds: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_SOFT_TTL_SECONDS", 600))
    hard_ttl_seconds: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_HARD_TTL_SECONDS", 3600))
    require_distributed_verification: bool = field(default_factory=lambda: _env_bool("RESOLVER_IDENTITY_REQUIRE_DISTRIBUTED_VERIFICATION", False))
    agent_timeout_seconds: float = field(default_factory=lambda: _env_float("RESOLVER_IDENTITY_AGENT_TIMEOUT_SECONDS", 2.0))
    verification_deadline_seconds: float = field(default_factory=lambda: _env_float("RESOLVER_IDENTITY_VERIFICATION_DEADLINE_SECONDS", 1.5))
    agent_tls_ca_file: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_TLS_CA_FILE", ""))
    agent_tls_client_cert_file: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_TLS_CLIENT_CERT_FILE", ""))
    agent_tls_client_key_file: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_TLS_CLIENT_KEY_FILE", ""))
    agent_plaintext_hosts: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_PLAINTEXT_HOSTS", "localhost,127.0.0.1"))

    registry_mode: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_REGISTRY_MODE", "sqlite"))
    web3_rpc_url: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_RPC_URL", ""))
    web3_contract_address: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS", ""))
    web3_chain_id: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_WEB3_CHAIN_ID", 31337))
    web3_abi_path: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_ABI_PATH", "contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json"))
    web3_sender_address: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_SENDER_ADDRESS", ""))
    web3_private_key_env: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_PRIVATE_KEY_ENV", ""))
    web3_private_key_file: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_PRIVATE_KEY_FILE", ""))
    web3_contract_code_hash: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_WEB3_CONTRACT_CODE_HASH", ""))
    web3_request_timeout_seconds: float = field(default_factory=lambda: _env_float("RESOLVER_IDENTITY_WEB3_REQUEST_TIMEOUT_SECONDS", 5.0))
    web3_transaction_timeout_seconds: float = field(default_factory=lambda: _env_float("RESOLVER_IDENTITY_WEB3_TRANSACTION_TIMEOUT_SECONDS", 120.0))
    watcher_confirmations: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_WATCHER_CONFIRMATIONS", 2))

    agent_resolver_id: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_RESOLVER_ID", "configured/resolver"))
    agent_endpoint_ip: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_ENDPOINT_IP", "127.0.0.1"))
    agent_endpoint_port: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_AGENT_ENDPOINT_PORT", 53))
    agent_endpoint_transport: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_ENDPOINT_TRANSPORT", "udp"))
    agent_config_version: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_CONFIG_VERSION", "1"))
    agent_issuer: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_ISSUER", "resolver-agent"))
    agent_key_id: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_KEY_ID", "agent-key-01"))
    agent_signature_secret: str = field(default_factory=lambda: _secret("RESOLVER_IDENTITY_AGENT_SIGNATURE_SECRET", _secret("RESOLVER_IDENTITY_SIGNATURE_SECRET", "prototype-secret")))
    agent_private_key_b64: str = field(default_factory=lambda: _secret("RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64", ""))
    agent_max_age_seconds: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_AGENT_MAX_AGE_SECONDS", 30))
    agent_base_urls: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_BASE_URLS", ""))
    agent_upstream_agent_base_urls: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_UPSTREAM_AGENT_BASE_URLS", _env("RESOLVER_IDENTITY_AGENT_BASE_URLS", "")))
    agent_terminal_upstreams: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_AGENT_TERMINAL_UPSTREAMS", ""))
    agent_max_chain_depth: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_AGENT_MAX_CHAIN_DEPTH", 4))

    metrics_host: str = field(default_factory=lambda: _env("RESOLVER_IDENTITY_METRICS_HOST", "127.0.0.1"))
    metrics_port: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_METRICS_PORT", 9108))
    max_inflight_queries: int = field(default_factory=lambda: _env_int("RESOLVER_IDENTITY_MAX_INFLIGHT_QUERIES", 512))
    persist_query_audit: bool = field(default_factory=lambda: _env_bool("RESOLVER_IDENTITY_PERSIST_QUERY_AUDIT", False))

    @property
    def production(self) -> bool:
        return self.environment.strip().lower() == "production"

    @property
    def db_file(self) -> Path:
        return Path(self.db_path)

    def validate_for(self, service: str) -> None:
        environment = self.environment.strip().lower()
        if environment not in {"production", "development", "test"}:
            raise ValueError(
                "RESOLVER_IDENTITY_ENVIRONMENT must be production, development, or test"
            )
        if self.soft_ttl_seconds <= 0 or self.hard_ttl_seconds <= 0:
            raise ValueError("cache TTLs must be positive")
        if self.soft_ttl_seconds > self.hard_ttl_seconds:
            raise ValueError("soft TTL must not exceed hard TTL")
        if self.verification_deadline_seconds <= 0:
            raise ValueError("verification deadline must be positive")
        if self.max_inflight_queries < 1:
            raise ValueError("maximum inflight query count must be positive")
        if not self.production:
            return
        if bool(self.agent_tls_client_cert_file) != bool(self.agent_tls_client_key_file):
            raise ValueError("Agent mTLS client certificate and key must be configured together")
        if self.registry_mode.lower() != "web3":
            raise ValueError("production requires RESOLVER_IDENTITY_REGISTRY_MODE=web3")
        if not self.web3_rpc_url or not self.web3_contract_address:
            raise ValueError("production requires Web3 RPC URL and contract address")
        if not self.web3_rpc_url.lower().startswith("https://"):
            raise ValueError("production Web3 RPC URL must use HTTPS")
        if self.web3_contract_address.lower() == "0x" + "0" * 40:
            raise ValueError("production Registry contract address must not be the zero address")
        if not self.web3_contract_code_hash:
            raise ValueError("production requires a pinned Registry contract code hash")
        try:
            valid_code_hash = len(self.web3_contract_code_hash) == 66 and int(self.web3_contract_code_hash[2:], 16) != 0
        except ValueError:
            valid_code_hash = False
        if not self.web3_contract_code_hash.startswith("0x") or not valid_code_hash:
            raise ValueError("production Registry contract code hash must be a nonzero bytes32 hex value")
        if self.allow_hmac_object_signatures:
            raise ValueError("production must disable HMAC resolver object signatures")
        if not self.issuer_keys_file:
            raise ValueError("production requires a pinned issuer key bundle")
        if service == "wrapper":
            if not self.require_distributed_verification:
                raise ValueError("production wrapper must require distributed verification")
            if not self.agent_base_urls:
                raise ValueError("production wrapper requires a first-hop Agent URL")
            validate_agent_url_config(self.agent_base_urls, self.agent_plaintext_host_set())
        if service == "agent" and not self.agent_private_key_b64:
            raise ValueError("production Agent requires an Ed25519 private key")
        if service == "agent":
            validate_agent_url_config(self.agent_upstream_agent_base_urls, self.agent_plaintext_host_set())
        if service == "admin":
            if not self.admin_api_token:
                raise ValueError("production Admin API requires an authentication token")
            if not self.issuer_private_key_b64:
                raise ValueError("production Admin requires an Ed25519 issuer private key")
        if service == "registry-writer":
            private_key_sources = sum(
                bool(value)
                for value in (
                    self.web3_private_key_env,
                    self.web3_private_key_file,
                )
            )
            if private_key_sources != 1:
                raise ValueError(
                    "production Registry writer requires exactly one transaction private key source"
                )

    def upstream_specs(self) -> list[tuple[str, int, str]]:
        specs = [(self.upstream_ip, self.upstream_port, self.upstream_transport)]
        specs.extend(_parse_endpoint_specs(self.fallback_upstreams, self.upstream_transport))
        return specs

    def agent_endpoint(self) -> ResolverEndpoint:
        return ResolverEndpoint(ip=self.agent_endpoint_ip, port=self.agent_endpoint_port, transport=self.agent_endpoint_transport).normalized()

    def agent_upstreams(self) -> list[ResolverEndpoint]:
        return [ResolverEndpoint(ip=ip, port=port, transport=transport).normalized() for ip, port, transport in self.upstream_specs()]

    def agent_terminal_upstream_endpoints(self) -> list[ResolverEndpoint]:
        return [ResolverEndpoint(ip=ip, port=port, transport=transport).normalized() for ip, port, transport in _parse_endpoint_specs(self.agent_terminal_upstreams, self.upstream_transport)]

    def agent_plaintext_host_set(self) -> set[str]:
        return {item.strip().lower() for item in self.agent_plaintext_hosts.split(",") if item.strip()}


def _parse_endpoint_specs(raw_value: str, default_transport: str) -> list[tuple[str, int, str]]:
    specs: list[tuple[str, int, str]] = []
    for raw in raw_value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split(":")
        if len(parts) == 1:
            specs.append((parts[0], 53, default_transport))
        elif len(parts) == 2:
            specs.append((parts[0], int(parts[1]), default_transport))
        else:
            specs.append((parts[0], int(parts[1]), parts[2]))
    return specs


def load_settings(service: str | None = None) -> Settings:
    settings = Settings()
    if service:
        settings.validate_for(service)
    return settings
