from __future__ import annotations

from fastapi import Body, FastAPI

from resolver_identity.agent.distributed_verifier import DistributedAgentVerifier
from resolver_identity.agent.identity import build_agent_identity, build_agent_identity_ed25519
from resolver_identity.common.config import load_settings
from resolver_identity.common.http_security import MaxRequestBodySizeMiddleware
from resolver_identity.common.health import probe_database, probe_registry
from resolver_identity.common.registry_factory import create_registry_backend
from resolver_identity.common.agent_transport import AgentTLSConfig
from resolver_identity.crypto.keys import load_issuer_key_registry
from resolver_identity.db.repositories import IndexerRepository, RegistryRepository, TrustedCacheRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier


def create_app() -> FastAPI:
    settings = load_settings("agent")
    app = FastAPI(title="Resolver Identity Agent")
    app.add_middleware(MaxRequestBodySizeMiddleware, max_bytes=65536)

    def identity_payload():
        if settings.agent_private_key_b64:
            return build_agent_identity_ed25519(
                resolver_id=settings.agent_resolver_id,
                endpoint=settings.agent_endpoint(),
                upstreams=settings.agent_upstreams(),
                config_version=settings.agent_config_version,
                private_key_b64=settings.agent_private_key_b64,
                max_age_seconds=settings.agent_max_age_seconds,
                health="ok",
                issuer=settings.agent_issuer,
                key_id=settings.agent_key_id,
            )
        return build_agent_identity(
            resolver_id=settings.agent_resolver_id,
            endpoint=settings.agent_endpoint(),
            upstreams=settings.agent_upstreams(),
            config_version=settings.agent_config_version,
            signature_secret=settings.agent_signature_secret,
            max_age_seconds=settings.agent_max_age_seconds,
            health="ok",
            issuer=settings.agent_issuer,
            key_id=settings.agent_key_id,
        )

    def verification_chain_payload(challenge: str | None = None):
        if not settings.agent_private_key_b64:
            raise RuntimeError("distributed verification chain requires RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64")
        conn = connect(settings.db_path)
        try:
            init_db(conn)
            registry_repository = RegistryRepository(conn)
            registry = create_registry_backend(settings, registry_repository)
            verifier = ResolverVerifier(
                IndexerRepository(conn),
                registry,
                CacheManager(TrustedCacheRepository(conn)),
                VerificationPolicy({"udp", "tcp", "doh"}, settings.soft_ttl_seconds, settings.hard_ttl_seconds),
                settings.signature_secret,
                issuer_keys=load_issuer_key_registry(settings.issuer_keys_file),
                allow_hmac_signatures=settings.allow_hmac_object_signatures,
            )
            distributed = DistributedAgentVerifier.from_raw_agent_urls(
                resolver_id=settings.agent_resolver_id,
                endpoint=settings.agent_endpoint(),
                upstreams=settings.agent_upstreams(),
                config_version=settings.agent_config_version,
                private_key_b64=settings.agent_private_key_b64,
                verifier=verifier,
                raw_agent_base_urls=settings.agent_upstream_agent_base_urls,
                terminal_upstreams=settings.agent_terminal_upstream_endpoints(),
                max_age_seconds=settings.agent_max_age_seconds,
                max_depth=settings.agent_max_chain_depth,
                timeout_seconds=settings.agent_timeout_seconds,
                tls_config=AgentTLSConfig(
                    settings.agent_tls_ca_file or None,
                    settings.agent_tls_client_cert_file or None,
                    settings.agent_tls_client_key_file or None,
                ),
                issuer=settings.agent_issuer,
                key_id=settings.agent_key_id,
            )
            return distributed.build_chain_payload(challenge=challenge)
        finally:
            conn.close()

    @app.get("/v1/identity")
    def identity():
        return identity_payload()

    @app.get("/v1/upstreams")
    def upstreams():
        payload = identity_payload()
        return {
            "resolver_id": payload["resolver_id"],
            "endpoint": payload["endpoint"],
            "upstreams": payload["upstreams"],
            "config_version": payload["config_version"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "signature": payload["signature"],
        }

    @app.get("/v1/verification-chain")
    def verification_chain():
        return verification_chain_payload()

    @app.post("/v1/verification-chain")
    def challenged_verification_chain(payload: dict = Body(...)):
        challenge = payload.get("challenge")
        if not isinstance(challenge, str) or len(challenge) < 32 or len(challenge) > 256:
            from fastapi import HTTPException

            raise HTTPException(status_code=422, detail="challenge must be a 32-256 character string")
        return verification_chain_payload(challenge)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "resolver_id": settings.agent_resolver_id, "config_version": settings.agent_config_version}

    @app.get("/readyz")
    def readyz():
        conn = connect(settings.db_path)
        try:
            init_db(conn)
            database = probe_database(conn)
            registry = create_registry_backend(settings, RegistryRepository(conn))
            return {"ok": True, "database": database, "registry": probe_registry(registry)}
        finally:
            conn.close()

    # Backward-compatible aliases for the earlier prototype stub.
    @app.get("/v1/agent/identity")
    def legacy_identity():
        return identity_payload()

    @app.get("/v1/agent/observed-resolvers")
    def legacy_observed_resolvers():
        payload = identity_payload()
        return {"observed_resolvers": [payload["endpoint"], *payload["upstreams"]], "signature": payload["signature"]}

    @app.get("/v1/agent/verification-chain")
    def legacy_verification_chain():
        return verification_chain_payload()

    return app


app = create_app()
