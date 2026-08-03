"""Canonical Management Ed25519 key loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PEM_BEGIN = b"-----BEGIN "
PEM_END = b"-----"
PRIVATE_LABEL = b"PRIVATE" + b" KEY"
OPENSSH_LABEL = b"OPENSSH " + PRIVATE_LABEL
ENCRYPTED_LABEL = b"ENCRYPTED " + PRIVATE_LABEL


class KeyMaterialError(ValueError):
    pass


def _read(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise KeyMaterialError("key is not a non-empty regular file")
    if path.stat().st_mode & 0o777 != 0o600:
        raise KeyMaterialError("key permissions must be 0600")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise KeyMaterialError("key cannot be read") from exc


def load_pkcs8_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    data = _read(path)
    if not data.startswith(PEM_BEGIN + PRIVATE_LABEL + PEM_END) or PEM_BEGIN + ENCRYPTED_LABEL + PEM_END in data:
        raise KeyMaterialError("issuer key must be unencrypted PKCS#8 PEM")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("issuer key is not valid unencrypted PKCS#8 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyMaterialError("key algorithm must be Ed25519")
    return key


def load_openssh_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    data = _read(path)
    if not data.startswith(PEM_BEGIN + OPENSSH_LABEL + PEM_END):
        raise KeyMaterialError("publication identity must be OpenSSH private key")
    try:
        key = serialization.load_ssh_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("publication identity is not valid unencrypted OpenSSH Ed25519") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyMaterialError("key algorithm must be Ed25519")
    return key


def load_management_issuer_key(path: Path) -> Ed25519PrivateKey:
    return load_pkcs8_ed25519_private_key(path)
