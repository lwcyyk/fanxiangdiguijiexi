#!/usr/bin/env python3
"""Build identities-v2.unsigned.json and issuer-keys.json on the management host
for the resolver-identity lab, following the frozen acceptance flow. Reads the
per-resolver Ed25519 seeds (base64) copied under <work>/agents/ and derives the
raw public keys; management issuer publics are derived from the same seeds that
back the PKCS#8 PEM files validated by key_material.validate_management_keys.
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path("/opt/domain-center-install/cloud-928ed0e")
WORK = ROOT / "work"
SECRET = ROOT / "secret"
MGMT_SECRET = SECRET

RESOLVERS = [
    {"host": "ri-r1", "server_id": "operator/L01/r1", "agent_key_id": "agent-key-L01-r1", "ip": "10.206.16.14", "role": "RECURSIVE"},
    {"host": "ri-r2", "server_id": "operator/L01/r2", "agent_key_id": "agent-key-L01-r2", "ip": "10.206.16.17", "role": "FORWARDER"},
    {"host": "ri-r3", "server_id": "operator/L01/r3", "agent_key_id": "agent-key-L01-r3", "ip": "10.206.16.7", "role": "FORWARDER"},
]


def public_from_seed_b64(seed_b64: str) -> str:
    seed = base64.b64decode(seed_b64.strip())
    if len(seed) != 32:
        raise SystemExit(f"bad seed length {len(seed)}")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(public_raw).decode("ascii")


def load_seed(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing seed file: {path}")
    return path.read_text(encoding="ascii").strip()


def main() -> int:
    identity_public = public_from_seed_b64(load_seed(MGMT_SECRET / "identity-issuer.key"))
    snapshot_public = public_from_seed_b64(load_seed(MGMT_SECRET / "snapshot-issuer.key"))

    now = int(time.time())
    identities: list[dict] = []
    for r in RESOLVERS:
        seed = load_seed(WORK / "agents" / r["host"] / "agent_private_key")
        agent_public = public_from_seed_b64(seed)
        identities.append(
            {
                "schema_version": "dns-server-identity-v2",
                "server_id": r["server_id"],
                "operator_id": "operator",
                "role": r["role"],
                "endpoints": [
                    {"ip": r["ip"], "port": 53, "transport": "udp"},
                    {"ip": r["ip"], "port": 53, "transport": "tcp"},
                ],
                "anycast": False,
                "agent": {
                    "key_id": r["agent_key_id"],
                    "algorithm": "ed25519",
                    "public_key": agent_public,
                    "service_url": f"https://{r['host']}:8443",
                },
                "valid_from": now - 60,
                "valid_until": now + 86400,
                "object_version": 1,
                "status": "ACTIVE",
                "issuer": "field-identity-authority",
                "key_id": "identity-key-1",
            }
        )
    issuer_keys = {
        "keys": [
            {"issuer": "field-identity-authority", "key_id": "identity-key-1", "algorithm": "ed25519", "public_key": identity_public},
            {"issuer": "norn-registry", "key_id": "snapshot-key-1", "algorithm": "ed25519", "public_key": snapshot_public},
        ]
    }
    (WORK / "identities-v2.unsigned.json").write_text(
        json.dumps({"identities": identities}, indent=2) + "\n", encoding="utf-8"
    )
    (WORK / "issuer-keys.json").write_text(
        json.dumps(issuer_keys, indent=2) + "\n", encoding="utf-8"
    )
    print(f"built identities for {len(identities)} resolvers; issuer-keys for {len(issuer_keys['keys'])} issuers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
