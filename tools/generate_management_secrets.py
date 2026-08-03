#!/usr/bin/env python3
"""Generate non-production Management key fixtures."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PRODUCT_KIT = Path(__file__).resolve().parents[1] / "deploy" / "easy-install" / "product-kit" / "common"
sys.path.insert(0, str(PRODUCT_KIT))
from key_material import key_metadata, validate_management_keys  # noqa: E402

NAMES = (
    "identity-issuer-ed25519-private-key",
    "snapshot-issuer-ed25519-private-key",
    "publication-ssh-identity",
)


def _safe_root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or path in {Path("/"), Path("/etc"), Path("/var"), Path("/home"), Path("/opt")}:
        raise ValueError("secret directory must be a dedicated absolute real directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    try:
        os.chown(path, 0, 0)
    except PermissionError as exc:
        raise ValueError("secret directory must be owned by root:root") from exc
    if path.stat().st_mode & 0o077:
        raise ValueError("secret directory permissions must be 0700")
    return path


def _exclusive_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
        try:
            os.chown(path, 0, 0)
        except PermissionError as exc:
            raise ValueError("generated key must be owned by root:root") from exc
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def generate(root: Path, *, test_only: bool) -> dict[str, object]:
    if not test_only:
        raise ValueError("--test-only is required; this generator never creates production secrets")
    if os.geteuid() != 0:
        raise ValueError("test-only Management secret generation must run as root")
    root = _safe_root(root)
    if any((root / name).exists() or (root / name).is_symlink() for name in NAMES):
        raise FileExistsError("refusing to overwrite an existing Management secret")

    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    enc = serialization.NoEncryption()
    issuer_data = [
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
        for key in keys[:2]
    ]
    publication_data = keys[2].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc)
    for name, data in zip(NAMES, (*issuer_data, publication_data)):
        _exclusive_write(root / name, data)

    metadata = validate_management_keys(root)
    return {
        "test_only": True,
        "warning": "TEST ONLY — NOT FOR PRODUCTION",
        "secret_dir": str(root),
        "files": metadata,
        "permissions": {"directory": "0700", "files": "0600"},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Management test-only Ed25519 secrets")
    parser.add_argument("--secret-dir", required=True, type=Path)
    parser.add_argument("--test-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(generate(args.secret_dir, test_only=args.test_only), ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError, FileExistsError) as exc:
        print(f"generator blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
