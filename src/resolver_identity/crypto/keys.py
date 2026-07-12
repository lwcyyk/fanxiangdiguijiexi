from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class IssuerPublicKey:
    issuer: str
    key_id: str
    algorithm: str
    public_key: str


class IssuerKeyRegistry:
    """In-memory issuer key registry used by the prototype verifier.

    Production deployments should source this from a pinned trust bundle or
    independently authenticated management channel, not from the resolver being
    verified.
    """

    def __init__(self, keys: list[IssuerPublicKey] | None = None):
        self._keys: dict[tuple[str, str], IssuerPublicKey] = {}
        for key in keys or []:
            self.add(key)

    def add(self, key: IssuerPublicKey) -> None:
        self._keys[(key.issuer, key.key_id)] = key

    def get(self, issuer: str, key_id: str) -> IssuerPublicKey | None:
        return self._keys.get((issuer, key_id))

    @classmethod
    def from_dicts(cls, items: list[dict]) -> "IssuerKeyRegistry":
        return cls([IssuerPublicKey(item["issuer"], item["key_id"], item["algorithm"], item["public_key"]) for item in items])

    @classmethod
    def from_file(cls, path: str | Path) -> "IssuerKeyRegistry":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("keys") if isinstance(data, dict) else data
        if not isinstance(items, list) or not items:
            raise ValueError("issuer key bundle must contain a non-empty keys list")
        registry = cls.from_dicts(items)
        for item in items:
            if str(item.get("algorithm", "")).lower() != "ed25519":
                raise ValueError("issuer key bundle only supports Ed25519 keys")
        return registry


def load_issuer_key_registry(path: str) -> IssuerKeyRegistry | None:
    return IssuerKeyRegistry.from_file(path) if path else None
