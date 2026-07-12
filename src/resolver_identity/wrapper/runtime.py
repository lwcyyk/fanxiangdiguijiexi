from __future__ import annotations

import argparse
import asyncio
from functools import partial

from resolver_identity.common.config import load_settings
from resolver_identity.common.registry_factory import create_registry_backend
from resolver_identity.db.repositories import RegistryRepository, RuntimeStateRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.common.agent_transport import AgentTLSConfig
from resolver_identity.common.health import probe_database, probe_registry
from resolver_identity.crypto.keys import load_issuer_key_registry
from resolver_identity.wrapper.dns_tcp import handle_tcp_dns
from resolver_identity.wrapper.dns_udp import UDPDNSServer
from resolver_identity.wrapper.query_processor import UpstreamResolver
from resolver_identity.wrapper.resolver_chain import AgentResolverChainProvider, parse_agent_base_urls
from resolver_identity.wrapper.monitoring import start_monitoring_server


def parse_upstream_specs(primary_ip: str, primary_port: int, primary_transport: str, fallbacks: str) -> list[UpstreamResolver]:
    specs = [UpstreamResolver(primary_ip, primary_port, primary_transport)]
    for raw in fallbacks.split(","):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split(":")
        if len(parts) == 1:
            specs.append(UpstreamResolver(parts[0], 53, primary_transport))
        elif len(parts) == 2:
            specs.append(UpstreamResolver(parts[0], int(parts[1]), primary_transport))
        else:
            specs.append(UpstreamResolver(parts[0], int(parts[1]), parts[2]))
    return specs


async def serve_dns(
    bind_host: str,
    udp_port: int | None,
    tcp_port: int | None,
    upstream_ip: str,
    upstream_port: int,
    upstream_transport: str,
    fallback_upstreams: str,
    db_path: str,
    signature_secret: str,
    agent_base_urls: str = "",
    require_distributed_verification: bool = False,
    issuer_keys_file: str = "",
    allow_hmac_signatures: bool = True,
    metrics_host: str = "127.0.0.1",
    metrics_port: int | None = 9108,
) -> None:
    settings = load_settings()
    chain_provider = None
    if agent_base_urls:
        chain_provider = AgentResolverChainProvider(
            parse_agent_base_urls(agent_base_urls),
            signature_secret=signature_secret,
            timeout_seconds=settings.agent_timeout_seconds,
            strict=True,
            require_challenge=settings.production,
            tls_config=AgentTLSConfig(
                settings.agent_tls_ca_file or None,
                settings.agent_tls_client_cert_file or None,
                settings.agent_tls_client_key_file or None,
            ),
        )
    elif require_distributed_verification:
        raise ValueError("distributed verification is required but no Agent URL is configured")
    registry = None
    if settings.registry_mode.lower() == "web3":
        conn = connect(db_path)
        init_db(conn)
        registry = create_registry_backend(settings, RegistryRepository(conn))
    stack = create_prototype_stack(
        db_path=db_path,
        signature_secret=signature_secret,
        chain_provider=chain_provider,
        registry=registry,
        issuer_keys=load_issuer_key_registry(issuer_keys_file),
        allow_hmac_signatures=allow_hmac_signatures,
        query_audit_enabled=settings.persist_query_audit,
    )
    if chain_provider is not None:
        chain_provider.state_repository = RuntimeStateRepository(stack.conn)
    stack.coordinator.verification_deadline_seconds = settings.verification_deadline_seconds
    upstreams = parse_upstream_specs(upstream_ip, upstream_port, upstream_transport, fallback_upstreams)
    loop = asyncio.get_running_loop()
    servers = []
    transports = []
    monitoring_server = None

    if udp_port is not None:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPDNSServer(stack.coordinator, upstreams, max_inflight=settings.max_inflight_queries),
            local_addr=(bind_host, udp_port),
        )
        transports.append(transport)
        print(f"UDP DNS wrapper listening on {bind_host}:{udp_port}, upstreams {upstreams}")

    if tcp_port is not None:
        server = await asyncio.start_server(
            partial(handle_tcp_dns, coordinator=stack.coordinator, upstreams=upstreams),
            bind_host,
            tcp_port,
        )
        servers.append(server)
        print(f"TCP DNS wrapper listening on {bind_host}:{tcp_port}, upstreams {upstreams}")

    if not servers and not transports:
        raise SystemExit("enable at least one of --udp-port or --tcp-port")

    if metrics_port is not None:
        def readiness_check() -> None:
            probe_database(stack.conn)
            probe_registry(stack.registry)

        monitoring_server = await start_monitoring_server(
            metrics_host,
            metrics_port,
            stack.coordinator.metrics,
            readiness_check=readiness_check,
        )
        print(f"Monitoring listening on http://{metrics_host}:{metrics_port}")

    try:
        await asyncio.Future()
    finally:
        for transport in transports:
            transport.close()
        for server in servers:
            server.close()
            await server.wait_closed()
        if monitoring_server is not None:
            monitoring_server.close()
            await monitoring_server.wait_closed()


def main() -> None:
    settings = load_settings("wrapper")
    parser = argparse.ArgumentParser(description="Run local UDP/TCP DNS verification wrapper")
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--udp-port", type=int, default=1053, help="local UDP DNS port; use --no-udp to disable")
    parser.add_argument("--tcp-port", type=int, default=1053, help="local TCP DNS port; use --no-tcp to disable")
    parser.add_argument("--no-udp", action="store_true")
    parser.add_argument("--no-tcp", action="store_true")
    parser.add_argument("--upstream-ip", default=settings.upstream_ip)
    parser.add_argument("--upstream-port", type=int, default=settings.upstream_port)
    parser.add_argument("--upstream-transport", default=settings.upstream_transport)
    parser.add_argument("--fallback-upstream", default=settings.fallback_upstreams, help="comma-separated ip[:port[:transport]] fallback upstreams")
    parser.add_argument("--db", default=settings.db_path)
    parser.add_argument("--signature-secret", default=settings.signature_secret)
    parser.add_argument("--agent-base-urls", default=settings.agent_base_urls, help="comma-separated endpoint=url mappings for Resolver Identity Agents")
    parser.add_argument("--metrics-host", default=settings.metrics_host)
    parser.add_argument("--metrics-port", type=int, default=settings.metrics_port)
    parser.add_argument("--no-metrics", action="store_true")
    args = parser.parse_args()
    asyncio.run(
        serve_dns(
            args.bind_host,
            None if args.no_udp else args.udp_port,
            None if args.no_tcp else args.tcp_port,
            args.upstream_ip,
            args.upstream_port,
            args.upstream_transport,
            args.fallback_upstream,
            args.db,
            args.signature_secret,
            args.agent_base_urls,
            settings.require_distributed_verification,
            settings.issuer_keys_file,
            settings.allow_hmac_object_signatures,
            args.metrics_host,
            None if args.no_metrics else args.metrics_port,
        )
    )


if __name__ == "__main__":
    main()
