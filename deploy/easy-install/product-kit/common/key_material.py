#!/usr/bin/env python3
"""Strict Management Ed25519 key material parsing."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as exc:  # pragma: no cover - exercised through lifecycle error mapping
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = Any  # type: ignore[misc,assignment]
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


PEM_BEGIN = b"-----BEGIN "
PEM_END = b"-----"
PRIVATE_LABEL = b"PRIVATE" + b" KEY"
OPENSSH_LABEL = b"OPENSSH " + PRIVATE_LABEL
ENCRYPTED_LABEL = b"ENCRYPTED " + PRIVATE_LABEL


class KeyMaterialError(ValueError):
    """Raised when a Management key violates its external contract."""


def _require_crypto() -> None:
    if serialization is None:
        raise KeyMaterialError("cryptography dependency is unavailable")


def _read(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise KeyMaterialError("key is not a non-empty regular file")
    if path.stat().st_mode & 0o777 != 0o600:
        raise KeyMaterialError("key permissions must be 0600")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise KeyMaterialError("key cannot be read") from exc


def _ensure_ed25519(key: object) -> Any:
    _require_crypto()
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyMaterialError("key algorithm must be Ed25519")
    return key


def load_pkcs8_ed25519_private_key(path: Path) -> Any:
    """Load an unencrypted PKCS#8 PEM Ed25519 key."""
    _require_crypto()
    data = _read(path)
    if not data.startswith(PEM_BEGIN + PRIVATE_LABEL + PEM_END) or PEM_BEGIN + ENCRYPTED_LABEL + PEM_END in data:
        raise KeyMaterialError("issuer key must be unencrypted PKCS#8 PEM")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("issuer key is not valid unencrypted PKCS#8 PEM") from exc
    return _ensure_ed25519(key)


def load_openssh_ed25519_private_key(path: Path) -> Any:
    """Load an unencrypted OpenSSH Ed25519 private key."""
    _require_crypto()
    data = _read(path)
    if not data.startswith(PEM_BEGIN + OPENSSH_LABEL + PEM_END):
        raise KeyMaterialError("publication identity must be OpenSSH private key")
    try:
        key = serialization.load_ssh_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("publication identity is not valid unencrypted OpenSSH Ed25519") from exc
    return _ensure_ed25519(key)


def public_raw_bytes(key: Any) -> bytes:
    _require_crypto()
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_fingerprint(key: Any) -> str:
    return hashlib.sha256(public_raw_bytes(key)).hexdigest()


def private_seed_b64(key: Any) -> str:
    _require_crypto()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return base64.b64encode(raw).decode("ascii")


def key_metadata(key: Any, format_name: str) -> dict[str, str]:
    return {"format": format_name, "algorithm": "Ed25519", "public_key_sha256": public_fingerprint(key)}


def validate_management_keys(secret_dir: Path) -> dict[str, dict[str, str]]:
    identity = load_pkcs8_ed25519_private_key(secret_dir / "identity-issuer-ed25519-private-key")
    snapshot = load_pkcs8_ed25519_private_key(secret_dir / "snapshot-issuer-ed25519-private-key")
    publication = load_openssh_ed25519_private_key(secret_dir / "publication-ssh-identity")
    identity_public = public_raw_bytes(identity)
    snapshot_public = public_raw_bytes(snapshot)
    publication_public = public_raw_bytes(publication)
    if identity_public == snapshot_public:
        raise KeyMaterialError("issuer keys must be distinct")
    if publication_public in {identity_public, snapshot_public}:
        raise KeyMaterialError("publication identity must not reuse an issuer key")
    return {
        "identity-issuer-ed25519-private-key": key_metadata(identity, "PKCS#8 PEM"),
        "snapshot-issuer-ed25519-private-key": key_metadata(snapshot, "PKCS#8 PEM"),
        "publication-ssh-identity": key_metadata(publication, "OpenSSH private key"),
    }
