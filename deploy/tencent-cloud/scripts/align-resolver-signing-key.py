#!/usr/bin/env python3
"""Align a resolver's agent signing seed to its identity-bound key.

The Tencent Cloud deployment publishes each resolver identity binding the
public key of the resolver's TLS server key (secret/agent-tls/agent.key).
The agent signs evidence with secret/secrets/agent_private_key, which must be
the raw Ed25519 seed of that SAME keypair. During the original secret
distribution the signing seeds diverged from the identity-bound keys, so the
agent readiness gate fails with "local Agent key does not match the signed
identity".

This tool, run on a resolver host as root, makes the signing seed match the
identity-bound agent.key:
  1. preserves the divergent seed under backups/ (bytes preserved, never printed),
  2. rewrites secret/secrets/agent_private_key as the base64 raw 32-byte seed
     of secret/agent-tls/agent.key,
  3. preserves the original file mode/owner,
  4. verifies the new seed derives the identity-bound public key.

Only public keys and a match boolean are ever printed; private key bytes are
never written to stdout, logs, git, or the support bundle.
"""
from __future__ import annotations

import argparse
import base64
import os
import shutil
import stat
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = "/opt/domain-center-install/cloud-928ed0e"


def derive_pub_from_seed(seed_b64: str) -> str:
    seed = base64.b64decode(seed_b64.strip(), validate=True)
    if len(seed) != 32:
        raise SystemExit(f"seed is {len(seed)} bytes, expected 32")
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64.b64encode(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="resolver host id, e.g. ri-r3")
    parser.add_argument("--identity-public-key", help="base64 public key bound in the signed identity")
    parser.add_argument(
        "--identity-public-key-file",
        help="path to a file containing the base64 public key (no trailing newline); "
        "alternative to --identity-public-key so the value never crosses a shell boundary",
    )
    args = parser.parse_args()
    if args.identity_public_key and args.identity_public_key_file:
        raise SystemExit("pass exactly one of --identity-public-key / --identity-public-key-file")
    if args.identity_public_key_file:
        with open(args.identity_public_key_file, encoding="ascii") as handle:
            args.identity_public_key = handle.read().strip()
    if not args.identity_public_key:
        raise SystemExit("one of --identity-public-key / --identity-public-key-file is required")

    secret = f"{ROOT}/secret"
    source = f"{secret}/secrets/agent_private_key"
    tls_key = f"{secret}/agent-tls/agent.key"
    backups = f"{ROOT}/backups"

    if not os.path.isfile(source):
        raise SystemExit(f"missing {source}")
    if not os.path.isfile(tls_key):
        raise SystemExit(f"missing {tls_key}")

    # 1. derive the identity-bound seed from agent.key (never printed)
    der = subprocess.run(
        ["openssl", "pkey", "-in", tls_key, "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    if len(der) < 32:
        raise SystemExit("unexpected agent.key DER length")
    seed_b64 = base64.b64encode(der[-32:]).decode("ascii")
    if derive_pub_from_seed(seed_b64) != args.identity_public_key:
        raise SystemExit("agent.key does not derive the identity-bound public key; aborting")

    # 2. preserve the divergent seed
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = os.path.join(backups, f"{args.host}-agent_private_key-pre-alignment-{timestamp}.bak")
    shutil.copy2(source, backup)
    os.chmod(backup, 0o600)

    # 3. rewrite the signing seed; keep original mode/owner
    mode = stat.S_IMODE(os.stat(source).st_mode)
    owner = (os.stat(source).st_uid, os.stat(source).st_gid)
    tmp = source + ".new"
    with open(tmp, "w", encoding="ascii") as handle:
        handle.write(seed_b64)  # 44 bytes, no newline, matching the original format
    os.chmod(tmp, mode)
    os.chown(tmp, owner[0], owner[1])
    os.replace(tmp, source)

    # 4. verify (public material only)
    data = open(source, encoding="ascii").read().strip()
    derived = derive_pub_from_seed(data)
    print(f"backup: {backup}")
    print(f"signing_seed_bytes: {os.stat(source).st_size}")
    print(f"derived_public_key: {derived}")
    print(f"matches_identity: {derived == args.identity_public_key}")
    return 0 if derived == args.identity_public_key else 1


if __name__ == "__main__":
    raise SystemExit(main())
