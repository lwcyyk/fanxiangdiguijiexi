from __future__ import annotations

import base64
import hmac
import hashlib

from resolver_identity.crypto.canonical_json import canonical_json_bytes
from resolver_identity.crypto.keys import IssuerKeyRegistry

HMAC_PREFIX = "base64:hmac-sha256:"
ED25519_PREFIX = "base64:ed25519:"


def sign_object(obj_dict: dict, secret: str) -> str:
    return sign_object_hmac(obj_dict, secret)


def sign_object_hmac(obj_dict: dict, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), canonical_json_bytes(obj_dict), hashlib.sha256).digest()
    return HMAC_PREFIX + base64.b64encode(mac).decode("ascii")


def verify_object_signature(obj_dict: dict, secret: str) -> bool:
    signature = obj_dict.get("signature")
    if isinstance(signature, str) and signature.startswith(HMAC_PREFIX):
        expected = sign_object_hmac(obj_dict, secret)
        return hmac.compare_digest(signature, expected)
    return False


def sign_object_ed25519(obj_dict: dict, private_key_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(raw)
    signature = key.sign(canonical_json_bytes(obj_dict))
    return ED25519_PREFIX + base64.b64encode(signature).decode("ascii")


def verify_ed25519_signature(obj_dict: dict, public_key_b64: str) -> bool:
    signature = obj_dict.get("signature")
    if not isinstance(signature, str) or not signature.startswith(ED25519_PREFIX):
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw_public = base64.b64decode(public_key_b64)
        raw_signature = base64.b64decode(signature[len(ED25519_PREFIX):])
        public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        public_key.verify(raw_signature, canonical_json_bytes(obj_dict))
        return True
    except Exception:
        return False


def verify_object_signature_with_registry(obj_dict: dict, registry: IssuerKeyRegistry | None, fallback_secret: str | None = None) -> bool:
    signature = obj_dict.get("signature")
    if not isinstance(signature, str):
        return False
    if signature.startswith(HMAC_PREFIX):
        return fallback_secret is not None and verify_object_signature(obj_dict, fallback_secret)
    if not signature.startswith(ED25519_PREFIX) or registry is None:
        return False
    key = registry.get(obj_dict.get("issuer", ""), obj_dict.get("key_id", ""))
    if not key or key.algorithm.lower() != "ed25519":
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw_public = base64.b64decode(key.public_key)
        raw_signature = base64.b64decode(signature[len(ED25519_PREFIX):])
        public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        public_key.verify(raw_signature, canonical_json_bytes(obj_dict))
        return True
    except Exception:
        return False


def generate_ed25519_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode("ascii")
