from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from resolver_identity.common.config import load_settings
from resolver_identity.common.http_security import MaxRequestBodySizeMiddleware
from resolver_identity.common.health import probe_database, probe_registry
from resolver_identity.common.registry_factory import create_registry_backend
from resolver_identity.common.agent_transport import AgentTLSConfig
from resolver_identity.crypto.keys import load_issuer_key_registry
from resolver_identity.db.repositories import AuditLogRepository, IndexerRepository, RegistryRepository, RuntimeStateRepository, TrustedCacheRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier
from resolver_identity.wrapper.doh import build_doh_router
from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.request_journal import RequestJournal
from resolver_identity.wrapper.routes_cache import build_cache_router
from resolver_identity.wrapper.routes_proofs import build_proofs_router
from resolver_identity.wrapper.routes_verify import build_verify_router
from resolver_identity.wrapper.resolver_chain import AgentResolverChainProvider, parse_agent_base_urls


def create_app() -> FastAPI:
    settings = load_settings("wrapper")
    conn = connect(settings.db_path)
    init_db(conn)
    cache_repo = TrustedCacheRepository(conn)
    registry_repository = RegistryRepository(conn)
    registry = create_registry_backend(settings, registry_repository)
    verifier = ResolverVerifier(
        IndexerRepository(conn),
        registry,
        CacheManager(cache_repo),
        VerificationPolicy({"udp", "tcp", "doh"}, settings.soft_ttl_seconds, settings.hard_ttl_seconds),
        settings.signature_secret,
        issuer_keys=load_issuer_key_registry(settings.issuer_keys_file),
        allow_hmac_signatures=settings.allow_hmac_object_signatures,
    )
    journal = RequestJournal()
    chain_provider = None
    if settings.agent_base_urls:
        chain_provider = AgentResolverChainProvider(
            parse_agent_base_urls(settings.agent_base_urls),
            signature_secret=settings.signature_secret,
            timeout_seconds=settings.agent_timeout_seconds,
            strict=True,
            require_challenge=settings.production,
            state_repository=RuntimeStateRepository(conn),
            tls_config=AgentTLSConfig(
                settings.agent_tls_ca_file or None,
                settings.agent_tls_client_cert_file or None,
                settings.agent_tls_client_key_file or None,
            ),
        )
    elif settings.require_distributed_verification:
        raise ValueError("distributed verification is required but no Agent URL is configured")
    coordinator = QueryCoordinator(
        verifier,
        chain_provider=chain_provider,
        audit=AuditLogRepository(conn) if settings.persist_query_audit else None,
        journal=journal,
        verification_deadline_seconds=settings.verification_deadline_seconds,
    )
    upstreams = [UpstreamResolver(ip, port, transport) for ip, port, transport in settings.upstream_specs()]
    app = FastAPI(title="Local DNS Verification Wrapper")
    app.add_middleware(MaxRequestBodySizeMiddleware, max_bytes=65535)
    app.include_router(build_doh_router(coordinator, upstreams))
    app.include_router(build_verify_router(verifier))
    app.include_router(build_cache_router(cache_repo, verifier.cache, registry))
    app.include_router(build_proofs_router(journal))

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/readyz")
    def readyz():
        return {"ok": True, "database": probe_database(conn), "registry": probe_registry(registry)}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        return coordinator.metrics.render()

    return app

app = create_app()
