from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from pathlib import Path

from resolver_identity.crypto.signatures import generate_ed25519_keypair


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local production secrets and trust bundle")
    parser.add_argument("--deploy-dir", default="deploy")
    parser.add_argument("--issuer", default="resolver-trust-authority-01")
    parser.add_argument("--issuer-key-id", default="issuer-key-01")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    deploy_dir = Path(args.deploy_dir).resolve()
    secrets_dir = deploy_dir / "secrets"
    env_target = deploy_dir.parent / ".env.production"
    issuer_bundle = deploy_dir / "issuer-keys.json"
    targets = [
        secrets_dir / "admin_api_token",
        secrets_dir / "agent_private_key_b64",
        secrets_dir / "issuer_private_key_b64",
        secrets_dir / "web3_private_key",
        issuer_bundle,
    ]
    existing = [path for path in targets if path.exists()]
    if existing and not args.force:
        raise SystemExit("refusing to overwrite existing production material: " + ", ".join(str(path) for path in existing))

    agent_private, agent_public = generate_ed25519_keypair()
    issuer_private, issuer_public = generate_ed25519_keypair()
    try:
        from eth_account import Account

        evm_account = Account.create()
        web3_private_key = evm_account.key.hex()
        web3_address = evm_account.address
    except ModuleNotFoundError:
        web3_private_key = "0x" + secrets.token_hex(32)
        web3_address = "derive-after-installing-web3"

    secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(secrets_dir, 0o700)
    write_secret(secrets_dir / "admin_api_token", secrets.token_urlsafe(48))
    write_secret(secrets_dir / "agent_private_key_b64", agent_private)
    write_secret(secrets_dir / "issuer_private_key_b64", issuer_private)
    write_secret(secrets_dir / "web3_private_key", web3_private_key)
    issuer_bundle.write_text(json.dumps({"keys": [{
        "issuer": args.issuer,
        "key_id": args.issuer_key_id,
        "algorithm": "ed25519",
        "public_key": issuer_public,
    }]}, indent=2) + "\n", encoding="utf-8")
    os.chmod(issuer_bundle, 0o644)

    template = deploy_dir.parent / ".env.production.example"
    if template.exists() and not env_target.exists():
        shutil.copyfile(template, env_target)
        os.chmod(env_target, 0o600)

    print(json.dumps({
        "deploy_dir": str(deploy_dir),
        "environment_file": str(env_target),
        "issuer_public_key": issuer_public,
        "agent_public_key": agent_public,
        "web3_publisher_address": web3_address,
        "next_step": "grant the Web3 publisher only the required registry roles, then edit .env.production",
    }, indent=2))


def write_secret(path: Path, value: str) -> None:
    path.write_text(value.strip() + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


if __name__ == "__main__":
    main()
