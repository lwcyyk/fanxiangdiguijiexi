#!/usr/bin/env python3
"""Generate the registry identities + issuer-keys for the Tencent Cloud lab.

Collects only *public* keys (base64 ed25519 raw) from the hosts:
  - resolver agent public keys: derived on each resolver host from
    secret/agent-tls/agent.key via `openssl pkey -pubout` (public key only;
    the private key is never read out or printed).
  - identity/snapshot issuer public keys: derived on the management host from
    the PEM private-key files via `openssl pkey -pubout` (public key only).

Writes identities-v2.unsigned.json and issuer-keys.json (public material) to
the given output dir. Mirrors the frozen acceptance harness's identity schema
(dns-server-identity-v2).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "config" / "site-inventory.json"
SECRET_ROOT = "/opt/domain-center-install/cloud-928ed0e/secret"
HOST_SECRET = "/opt/domain-center-install/cloud-928ed0e/secret"


def ssh_pubkey(alias: str, key_path: str, sudo: bool = False) -> str:
    """Derive the raw base64 ed25519 public key for a key file on a host."""
    cmd = f"openssl pkey -in {key_path} -pubout -outform DER 2>/dev/null | tail -c 32 | base64"
    if sudo:
        cmd = f"sudo -n bash -c '{cmd}'"
    result = subprocess.run(
        ["ssh", alias, cmd],
        check=True, capture_output=True, text=True,
    )
    pub = result.stdout.strip().splitlines()[-1]
    if not pub:
        raise RuntimeError(f"could not derive public key for {key_path} on {alias}")
    return pub


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/tmp/ri-registry-work"))
    args = parser.parse_args()
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    now = int(time.time())

    # ---- DNS server agent public keys (resolvers plus authoritative DNS) ----
    identities = []
    servers = [
        *inventory["resolvers"],
        {
            **inventory["authdns"],
            "resolver_ip": inventory["authdns"]["listen_ip"],
        },
    ]
    for server in servers:
        host = server["host"]
        alias = f"{host}-cloud"
        agent_pub = ssh_pubkey(
            alias,
            f"{HOST_SECRET}/agent-tls/agent.key",
            sudo=True,
        )
        identities.append(
            {
                "schema_version": "dns-server-identity-v2",
                "server_id": server["server_id"],
                "operator_id": "operator",
                "role": server["registry_role"],
                "endpoints": [
                    {"ip": server["resolver_ip"], "port": 53, "transport": "udp"},
                    {"ip": server["resolver_ip"], "port": 53, "transport": "tcp"},
                ],
                "anycast": False,
                "agent": {
                    "key_id": server["agent_key_id"],
                    "algorithm": "ed25519",
                    "public_key": agent_pub,
                    "service_url": f"https://{server['management_ip']}:8443",
                },
                "valid_from": now - 60,
                "valid_until": now + 604800,
                "object_version": 1,
                "status": "ACTIVE",
                "issuer": "field-identity-authority",
                "key_id": "identity-key-1",
            }
        )
        print(f"agent pubkey {host}: {agent_pub}")

    # ---- issuer public keys (identity + snapshot) from management PEMs ----
    identity_pub = ssh_pubkey(
        "ri-management-cloud",
        f"{SECRET_ROOT}/identity-issuer-ed25519-private-key",
        sudo=True,
    )
    snapshot_pub = ssh_pubkey(
        "ri-management-cloud",
        f"{SECRET_ROOT}/snapshot-issuer-ed25519-private-key",
        sudo=True,
    )
    print(f"identity-issuer pubkey: {identity_pub}")
    print(f"snapshot-issuer pubkey: {snapshot_pub}")

    issuer_keys = {
        "keys": [
            {
                "issuer": "field-identity-authority",
                "key_id": "identity-key-1",
                "algorithm": "ed25519",
                "public_key": identity_pub,
            },
            {
                "issuer": "norn-registry",
                "key_id": "snapshot-key-1",
                "algorithm": "ed25519",
                "public_key": snapshot_pub,
            },
        ]
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "identities-v2.unsigned.json").write_text(
        json.dumps({"identities": identities}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.output / "issuer-keys.json").write_text(
        json.dumps(issuer_keys, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote identities-v2.unsigned.json ({len(identities)} identities) and issuer-keys.json to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
