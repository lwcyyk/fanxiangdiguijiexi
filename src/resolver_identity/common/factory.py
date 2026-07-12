from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.chain.registry_client import SQLiteRegistryClient
from resolver_identity.chain.backend import RegistryBackend
from resolver_identity.crypto.keys import IssuerKeyRegistry
from resolver_identity.db.repositories import AuditLogRepository, IndexerRepository, RegistryRepository, TrustedCacheRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier
from resolver_identity.wrapper.query_coordinator import QueryCoordinator
from resolver_identity.wrapper.query_processor import DNSQueryProcessor
from resolver_identity.wrapper.request_journal import RequestJournal
from resolver_identity.wrapper.resolver_chain import ResolverChainProvider
from resolver_identity.wrapper.verification_gate import VerificationGate


@dataclass(slots=True)
class PrototypeStack:
    conn: sqlite3.Connection
    indexer: IndexerRepository
    registry_repository: RegistryRepository
    registry: RegistryBackend
    trusted_cache_repository: TrustedCacheRepository
    cache: CacheManager
    publisher: AdminPublisher
    verifier: ResolverVerifier
    journal: RequestJournal
    gate: VerificationGate
    processor: DNSQueryProcessor
    coordinator: QueryCoordinator


def create_prototype_stack(
    db_path: str = ":memory:",
    signature_secret: str = "prototype-secret",
    allowed_transports: set[str] | None = None,
    issuer_keys: IssuerKeyRegistry | None = None,
    ed25519_private_key_b64: str | None = None,
    chain_provider: ResolverChainProvider | None = None,
    registry: RegistryBackend | None = None,
    allow_hmac_signatures: bool = True,
    query_audit_enabled: bool = True,
) -> PrototypeStack:
    conn = connect(db_path) if db_path != ":memory:" else sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    indexer = IndexerRepository(conn)
    registry_repository = RegistryRepository(conn)
    registry = registry or SQLiteRegistryClient(registry_repository)
    trusted_cache_repository = TrustedCacheRepository(conn)
    cache = CacheManager(trusted_cache_repository)
    policy = VerificationPolicy(allowed_transports or {"udp", "tcp", "doh"})
    publisher = AdminPublisher(indexer, registry, signature_secret, ed25519_private_key_b64=ed25519_private_key_b64)
    verifier = ResolverVerifier(indexer, registry, cache, policy, signature_secret, issuer_keys=issuer_keys, allow_hmac_signatures=allow_hmac_signatures)
    journal = RequestJournal()
    gate = VerificationGate(verifier, journal)
    processor = DNSQueryProcessor(verifier, journal)
    coordinator = QueryCoordinator(
        verifier,
        chain_provider=chain_provider,
        audit=AuditLogRepository(conn) if query_audit_enabled else None,
        journal=journal,
    )
    return PrototypeStack(conn, indexer, registry_repository, registry, trusted_cache_repository, cache, publisher, verifier, journal, gate, processor, coordinator)
