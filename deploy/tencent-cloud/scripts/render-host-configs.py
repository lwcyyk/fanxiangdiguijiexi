#!/usr/bin/env python3
"""Render per-host runtime config dirs (.env, kresd.conf) for the Tencent Cloud
resolver-identity lab, following the frozen manage_norn_field_delivery.py
_render_host_configs contract. Extends the management .env with the SSH-tunnel
publication variables required by publish-norn.sh.

Dynamic values (norn genesis hash, node peer ids) are read from state.json so
configs can be re-rendered after norn-a starts.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # deploy/tencent-cloud
CONFIG_DIR = ROOT / "config"
INVENTORY = CONFIG_DIR / "site-inventory.json"
STATE = CONFIG_DIR / "state.json"
HOSTS_OUT = CONFIG_DIR / "hosts"


def _env_lines(values: dict[str, object]) -> str:
    return "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"


def render(inventory: dict, state: dict) -> list[Path]:
    release = inventory["release"]
    images = inventory["images"]
    management = inventory["management"]
    norn = inventory["norn"]
    network = release["field_network"]
    chain = {
        "chain_id": norn["chain_id"],
        "registry_address": norn["registry_address"],
        "registry_key": norn["registry_key"],
        "schema_hash": norn["schema_hash"],
        "snapshot_issuer": norn["snapshot_issuer"],
        "snapshot_key_id": norn["snapshot_key_id"],
        "confirmations": norn["confirmations"],
        "registry_start_height": norn["registry_start_height"],
        "max_scan_blocks": norn["max_scan_blocks"],
    }
    # Cross-host containers cannot resolve *.cloud.lab via host /etc/hosts, and
    # cloud VPC DNS does not know the field network. The norn server certs carry
    # IP SANs, so resolver registry-sync and management nornctl connect by IP.
    read_urls = ",".join(f"https://{node['read_ip']}:8443" for node in norn["nodes"])
    genesis_hash = state["norn"].get("genesis_hash") or "0x" + "0" * 64
    node_a_peer = state["norn"].get("node_a_peer_id")
    node_b_peer = state["norn"].get("node_b_peer_id")
    if node_a_peer is None:
        node_a_peer = "NODE_A_PEER_ID"
    if node_b_peer is None:
        node_b_peer = "NODE_B_PEER_ID"

    written: list[Path] = []

    # ---- management ----
    mgmt_env = {
        "RI_FIELD_HOST_ID": management["host"],
        "RI_FIELD_COMPOSE_PROJECT": management["host"],
        "RI_FIELD_NETWORK": network,
        "RI_FIELD_DATA_DIR": management["data_dir"],
        "RI_MANAGEMENT_IMAGE": images["management"],
        "RI_NORN_IMAGE": images["norn"],
        "RI_MANAGEMENT_WORK_DIR": management["work_dir"],
        "RI_MANAGEMENT_SECRET_DIR": management["secret_dir"],
        "RI_NORNCTL_TLS_DIR": management["norn_tls_dir"],
        "RI_NORN_PUBLISH_MODE": "ssh-tunnel",
        "RI_NORN_PUBLISH_TARGET": "127.0.0.1:45555",
        "RI_NORN_SIMULATION_PUBLISH_TARGET": f"{norn['nodes'][0]['host']}:45555",
        # SSH-tunnel publication transport (publish-norn.sh)
        "RI_NORN_SSH_KNOWN_HOSTS": "/opt/domain-center-install/cloud-928ed0e/ssh/publication_known_hosts",
        "RI_NORN_SSH_HOST": norn["nodes"][0]["management_ip"],
        "RI_NORN_SSH_USER": "ubuntu",
        "RI_NORN_SSH_PORT": "22",
        "RI_NORN_SSH_REMOTE_TARGET": "127.0.0.1:45555",
    }
    written.append(_write_host(HOSTS_OUT / management["host"] / "config", ".env", _env_lines(mgmt_env)))

    # ---- norn nodes ----
    for node in norn["nodes"]:
        bootstrap = ""
        if node["role"] == "node-b":
            # Docker embedded DNS only resolves same-host containers; the node-a
            # p2p endpoint must be the literal IP, not the *.cloud.lab name.
            bootstrap = f"/ip4/{norn['nodes'][0]['p2p_ip']}/tcp/31258/p2p/{node_a_peer}"
        node_env = {
            "RI_FIELD_HOST_ID": node["host"],
            "RI_FIELD_COMPOSE_PROJECT": node["host"],
            "RI_FIELD_NETWORK": network,
            "RI_FIELD_DATA_DIR": node["data_dir"],
            "RI_NORN_IMAGE": images["norn"],
            "RI_NGINX_IMAGE": images["nginx"],
            "RI_NORN_ROLE": node["role"],
            # Compose-network name the read proxy's grpc_pass resolves to the
            # node container. Docker writes the short label of a dotted
            # container hostname (the read proxy's RI_NORN_READ_HOSTNAME
            # ri-<node>.cloud.lab) into that container's /etc/hosts, so the
            # label equals the node hostname here and shadows the norn-node
            # network alias. Point the upstream at the compose service name
            # instead, which Docker DNS always resolves to the node container.
            "RI_NORN_NODE_HOSTNAME": "norn-node",
            # The frozen activate readiness probe (_norn_grpc_ready) uses
            # urllib (HTTP/1.1), which cannot read the grpc-status trailer that
            # nginx grpc_pass emits over HTTP/1.1, so it rejects the healthy
            # read proxy with NORN_HTTP_REJECTED. Point the probe at a local
            # probe-relay on 127.0.0.1:8443 (serving this host's norn server
            # cert, whose SAN includes localhost) that forwards to the real
            # read proxy and surfaces grpc-status as a header. The real read
            # proxy keeps serving RI_NORN_READ_BIND_ADDRESS:8443 for the
            # resolvers and management nornctl, which speak HTTP/2 and read
            # trailers correctly. This only changes the read proxy's cosmetic
            # container hostname/network alias; nothing else resolves it.
            "RI_NORN_READ_HOSTNAME": "localhost",
            "RI_NORN_CONFIG_DIR": node["config_dir"],
            "RI_NORN_TLS_DIR": node["tls_dir"],
            "RI_NORN_NATIVE_BIND_ADDRESS": "127.0.0.1",
            "RI_NORN_NATIVE_LOOPBACK_PORT": node["native_loopback_port"],
            "RI_NORN_P2P_BIND_ADDRESS": node["p2p_ip"],
            "RI_NORN_READ_BIND_ADDRESS": node["read_ip"],
            "RI_NORN_READ_PORT": "8443",
            "RI_NORN_BOOTSTRAP": bootstrap,
            "RI_NORN_UID": "10003",
            "RI_NORN_GID": "10003",
        }
        written.append(_write_host(HOSTS_OUT / node["host"] / "config", ".env", _env_lines(node_env)))

    # ---- resolvers ----
    for resolver in inventory["resolvers"]:
        upstreams = ",".join(resolver["wrapper_upstreams"])
        resolver_env = {
            "RI_FIELD_HOST_ID": resolver["host"],
            "RI_FIELD_COMPOSE_PROJECT": resolver["host"],
            "RI_FIELD_NETWORK": network,
            "RI_FIELD_DATA_DIR": resolver["data_dir"],
            "RI_MANAGEMENT_BIND_ADDRESS": resolver["management_ip"],
            "RI_IMAGE": images["rust"],
            "RI_KNOT_IMAGE": images["knot"],
            "RI_RESOLVER_ROLE": resolver["role"],
            "RI_VERIFICATION_MODE": "controlled-strict",
            "RI_AGENT_SERVER_ID": resolver["server_id"],
            "RI_AGENT_KEY_ID": resolver["agent_key_id"],
            "RI_CHAIN_ADAPTER": "norn",
            "RI_CHAIN_RPC_URLS": read_urls,
            "RI_CHAIN_ID": str(chain["chain_id"]),
            "RI_NORN_GENESIS_BLOCK_HASH": genesis_hash,
            "RI_CHAIN_REGISTRY_ADDRESS": chain["registry_address"],
            "RI_NORN_REGISTRY_KEY": chain["registry_key"],
            "RI_NORN_SIGNER_ISSUER": chain["snapshot_issuer"],
            "RI_NORN_SIGNER_KEY_ID": chain["snapshot_key_id"],
            "RI_CHAIN_REGISTRY_SCHEMA_HASH": chain["schema_hash"],
            "RI_CHAIN_CONFIRMATIONS": str(chain["confirmations"]),
            "RI_NORN_REGISTRY_START_HEIGHT": str(chain["registry_start_height"]),
            "RI_NORN_MAX_SCAN_BLOCKS": str(chain["max_scan_blocks"]),
            "RI_NORN_CLIENT_TLS_DIR": resolver["norn_tls_dir"],
            "RI_RESOLVER_SECRET_DIR": resolver["secret_dir"],
            "RI_AGENT_TLS_DIR": resolver["agent_tls_dir"],
            "RI_TRACE_SOCKET_HOST_DIR": resolver["trace_socket"],
            "RI_TRACE_PRODUCER_UID": str(resolver["trace_producer_uid"]),
            "RI_TRACE_PRODUCER_GID": str(resolver["trace_producer_gid"]),
            "RI_KNOT_RESOLVER_UID": "10003",
            "RI_EXISTING_RESOLVER_CONFIG_PATH": resolver["existing_resolver_config"],
            "RI_RESOLVER_BIND_ADDRESS": resolver["resolver_ip"],
            "RI_TRACE_MAX_CONTEXTS": "65536",
            "RI_TRACE_ACK_TIMEOUT_MS": "100",
            "RI_TRACE_CACHE_PROVENANCE_WAIT_MS": "2000",
            "RI_TRACE_WAIT_MILLIS": "5000",
            "RI_WRAPPER_AGENT_TIMEOUT_MS": "7500",
            "RI_WRAPPER_MAX_CONCURRENT_VERIFICATIONS": "32",
            "RI_WRAPPER_UPSTREAMS": upstreams,
            "DNS_BIND_ADDRESS": resolver["dns_ip"],
            "DNS_PORT": "53",
            "RI_REGISTRY_SYNC_ONCE": "false",
        }
        written.append(_write_host(HOSTS_OUT / resolver["host"] / "config", ".env", _env_lines(resolver_env)))
        written.append(_write_host(HOSTS_OUT / resolver["host"] / "config", "kresd.conf", _kresd_conf(resolver, inventory["authdns"])))

    # ---- authoritative DNS data plane ----
    authdns = inventory["authdns"]
    authdns_env = {
        "RI_FIELD_HOST_ID": authdns["host"],
        "RI_FIELD_COMPOSE_PROJECT": authdns["host"],
        "RI_FIELD_DATA_DIR": authdns["data_dir"],
        "RI_AUTHDNS_CONFIG_DIR": authdns["config_dir"],
        "RI_IMAGE": images["rust"],
        "RI_AUTHDNS_MANAGEMENT_IP": authdns["management_ip"],
        "RI_AGENT_SERVER_ID": authdns["server_id"],
        "RI_AGENT_KEY_ID": authdns["agent_key_id"],
        "RI_CHAIN_RPC_URLS": read_urls,
        "RI_CHAIN_ID": str(chain["chain_id"]),
        "RI_NORN_GENESIS_BLOCK_HASH": genesis_hash,
        "RI_CHAIN_REGISTRY_ADDRESS": chain["registry_address"],
        "RI_NORN_REGISTRY_KEY": chain["registry_key"],
        "RI_NORN_SIGNER_ISSUER": chain["snapshot_issuer"],
        "RI_NORN_SIGNER_KEY_ID": chain["snapshot_key_id"],
        "RI_CHAIN_REGISTRY_SCHEMA_HASH": chain["schema_hash"],
        "RI_CHAIN_CONFIRMATIONS": str(chain["confirmations"]),
        "RI_NORN_REGISTRY_START_HEIGHT": str(chain["registry_start_height"]),
        "RI_NORN_MAX_SCAN_BLOCKS": str(chain["max_scan_blocks"]),
        "RI_NORN_CLIENT_TLS_DIR": authdns["norn_tls_dir"],
        "RI_RESOLVER_SECRET_DIR": authdns["secret_dir"],
        "RI_AGENT_TLS_DIR": authdns["agent_tls_dir"],
        "RI_REGISTRY_MAX_STALENESS_SECONDS": "45",
        "RI_AUTHORITY_PUBLIC_BIND": f"{authdns['listen_ip']}:53",
        "RI_AUTHORITY_AGENT_URL": f"https://{authdns['management_ip']}:8443",
    }
    written.append(_write_host(HOSTS_OUT / authdns["host"] / "config", ".env", _env_lines(authdns_env)))
    return written


def _write_host(host_config_dir: Path, filename: str, content: str) -> Path:
    host_config_dir.mkdir(parents=True, exist_ok=True)
    path = host_config_dir / filename
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _kresd_conf(resolver: dict, authdns: dict) -> str:
    host = resolver["host"]
    forward_target = {
        "ri-r1": "10.206.16.17",  # R1 knot -> R2
        "ri-r2": "10.206.16.7",   # R2 knot -> R3
        "ri-r3": authdns["listen_ip"],  # R3 knot -> authoritative DNS
    }[host]
    anchors = "".join(
        f"trust_anchors.add({record!r})\n"
        for record in authdns.get("dnssec_trust_anchors", [])
    )
    return (
        "-- Managed by Resolver Identity Tencent Cloud lab. Validate before activation.\n"
        "net.listen('0.0.0.0', 1053, { kind = 'dns' })\n"
        "cache.size = 256 * MB\n"
        "modules = { 'hints > iterate', 'stats', 'policy' }\n"
        + anchors
        + "-- PASSTHRU_LEGACY bypasses only .invalid synthesis; FORWARD still validates DNSSEC.\n"
        + f"local forward = policy.FORWARD('{forward_target}@53')\n"
        + "local passthru = policy.FLAGS('PASSTHRU_LEGACY')\n"
        + "policy.add(policy.suffix(function(state, req)\n"
        + "    forward(state, req)\n"
        + "    passthru(state, req)\n"
        + "    return state\n"
        + "  end, { todname('ri-test.invalid.') }))\n"
    )


def main() -> int:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    state = json.loads(STATE.read_text(encoding="utf-8"))
    written = render(inventory, state)
    for path in written:
        print(f"rendered {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
