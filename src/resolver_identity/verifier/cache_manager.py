from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.common.time import parse_rfc3339, utc_now, format_rfc3339
from resolver_identity.db.repositories import TrustedCacheRepository
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.verifier.cache_keys import trusted_cache_key


class CacheManager:
    def __init__(self, repository: TrustedCacheRepository):
        self.repository = repository
        # Memory cache is indexed by endpoint lookup key, but each stored row also
        # has a full binding cache_key over resolver_id + endpoint + object_version.
        self.memory: dict[str, dict[str, Any]] = {}
        self._lock = RLock()
        self._generation_owner = str(uuid4())

    def get_valid(self, endpoint_key: str, observed: ResolverEndpoint, now: datetime | None = None) -> VerificationResult | None:
        now = now or utc_now()
        generation = self.repository.current_generation()
        # Prefer repository state so a separate event-watcher process can revoke
        # cache entries and the wrapper will observe it before trusting memory.
        row = self.repository.get_by_endpoint_lookup_key(endpoint_key) or self.memory.get(endpoint_key)
        if generation != self.repository.current_generation():
            return None
        if not row:
            return None
        status = row.get("status")
        if status == "REVOKED":
            return VerificationResult.reject("cache_revoked", row.get("resolver_id"))
        if status not in {"VERIFIED", "REFRESHING"}:
            return None
        hard = parse_rfc3339(row["hard_expire_at"])
        if hard <= now:
            self.invalidate_cache_key(row["cache_key"], "EXPIRED")
            self.memory.pop(endpoint_key, None)
            return None
        cached_endpoint = ResolverEndpoint.from_dict(row["endpoint"])
        if not cached_endpoint.matches(observed):
            return VerificationResult.reject("cache_endpoint_mismatch", row.get("resolver_id"))
        expected_binding_key = trusted_cache_key(cached_endpoint, row["resolver_id"], int(row["object_version"]))
        if row.get("cache_key") != expected_binding_key:
            return VerificationResult.reject("cache_binding_mismatch", row.get("resolver_id"))
        soft = parse_rfc3339(row["soft_expire_at"])
        effective_status = "REFRESHING" if soft <= now else "VERIFIED"
        if effective_status != row.get("status"):
            row["status"] = effective_status
            self.repository.update_status(row["cache_key"], effective_status)
        self.memory[endpoint_key] = row
        evidence = dict(row.get("evidence") or {})
        evidence.update({
            "cache": "hit" if effective_status == "VERIFIED" else "stale-hit-refreshing",
            "object_hash": row["object_hash"],
            "object_version": row["object_version"],
            "state_root": row["state_root"],
            "cache_generation": generation,
            "cache_generation_owner": self._generation_owner,
        })
        return VerificationResult.accept(
            row["resolver_id"],
            status=effective_status,
            **evidence,
        )

    def store_verified(self, endpoint_key: str, resolver_id: str, endpoint: ResolverEndpoint, object_hash: str, object_version: int, state_root: str, soft_expire_at: str, hard_expire_at: str, evidence: dict[str, Any], expected_generation: int | None = None) -> bool:
        endpoint = endpoint.normalized()
        cache_key = trusted_cache_key(endpoint, resolver_id, object_version)
        row = {
            "cache_key": cache_key,
            "endpoint_lookup_key": endpoint_key,
            "resolver_id": resolver_id,
            "endpoint": endpoint.to_dict(),
            "object_hash": object_hash,
            "object_version": object_version,
            "state_root": state_root,
            "status": "VERIFIED",
            "verified_at": format_rfc3339(utc_now()),
            "soft_expire_at": soft_expire_at,
            "hard_expire_at": hard_expire_at,
            "evidence": evidence,
        }
        generation = self.repository.current_generation() if expected_generation is None else expected_generation
        row["evidence"] = {
            **evidence,
            "cache_generation": generation,
            "cache_generation_owner": self._generation_owner,
        }
        with self._lock:
            stored = self.repository.put_if_generation(cache_key, row, generation)
            if stored:
                self.memory[endpoint_key] = row
        return stored

    def current_generation(self) -> int:
        return self.repository.current_generation()

    @property
    def generation_owner(self) -> str:
        return self._generation_owner

    def result_is_current(self, result: VerificationResult) -> bool:
        if result.evidence.get("cache_generation_owner") != self._generation_owner:
            return True
        generation = result.evidence.get("cache_generation")
        return generation is None or int(generation) == self.current_generation()

    def invalidate_cache_key(self, cache_key: str, status: str = "EXPIRED") -> None:
        self.repository.bump_generation()
        for endpoint_key, row in list(self.memory.items()):
            if row.get("cache_key") == cache_key:
                row["status"] = status
        self.repository.update_status(cache_key, status)

    def invalidate_endpoint_key(self, endpoint_key: str, status: str = "EXPIRED") -> None:
        row = self.memory.get(endpoint_key) or self.repository.get_by_endpoint_lookup_key(endpoint_key)
        if row:
            self.invalidate_cache_key(row["cache_key"], status)
        self.memory.pop(endpoint_key, None)

    def invalidate_endpoint(self, endpoint: ResolverEndpoint, status: str = "EXPIRED") -> None:
        endpoint_key = endpoint_lookup_key(endpoint)
        self.invalidate_endpoint_key(endpoint_key, status)

    def invalidate_resolver(self, resolver_id: str, status: str = "REVOKED") -> None:
        self.repository.bump_generation()
        for key, row in list(self.memory.items()):
            if row.get("resolver_id") == resolver_id:
                row["status"] = status
        self.repository.mark_status_by_resolver(resolver_id, status)

    def invalidate_resolver_key(self, resolver_id_key: str, status: str = "EXPIRED") -> None:
        self.repository.bump_generation()
        for endpoint_key, row in list(self.memory.items()):
            evidence = row.get("evidence") or {}
            if evidence.get("resolver_id_key") == resolver_id_key:
                row["status"] = status
        for row in self.repository.list():
            evidence = row.get("evidence") or {}
            if evidence.get("resolver_id_key") == resolver_id_key:
                self.invalidate_cache_key(row["cache_key"], status)

    def invalidate_object_version_by_resolver_key(self, resolver_id_key: str, object_version: int) -> None:
        self.repository.bump_generation()
        for endpoint_key, row in list(self.memory.items()):
            evidence = row.get("evidence") or {}
            if evidence.get("resolver_id_key") == resolver_id_key and int(row.get("object_version", -1)) != object_version:
                row["status"] = "EXPIRED"
        for row in self.repository.list():
            evidence = row.get("evidence") or {}
            if evidence.get("resolver_id_key") == resolver_id_key and int(row.get("object_version", -1)) != object_version:
                self.invalidate_cache_key(row["cache_key"], "EXPIRED")

    def invalidate_root(self, state_root: str, status: str = "REVOKED") -> None:
        self.repository.bump_generation()
        for key, row in list(self.memory.items()):
            if row.get("state_root") == state_root:
                row["status"] = status
        self.repository.mark_status_by_root(state_root, status)

    def invalidate_object_version(self, resolver_id: str, object_version: int) -> None:
        self.repository.bump_generation()
        for key, row in list(self.memory.items()):
            if row.get("resolver_id") == resolver_id and int(row.get("object_version", -1)) != object_version:
                row["status"] = "EXPIRED"
        self.repository.mark_stale_versions(resolver_id, object_version)

    def expire_all(self, status: str = "EXPIRED") -> int:
        rows = self.repository.list()
        for row in rows:
            self.invalidate_cache_key(row["cache_key"], status)
        self.memory.clear()
        return len(rows)

    def refresh_registry_state(self, registry) -> dict[str, int]:
        """Poll registry state and invalidate cache entries whose anchors changed.

        This is the explicit refresh path used before a real event watcher is
        attached. It does not fabricate chain events; it compares cached evidence
        with current registry bindings, anchors, and root status.
        """
        counts = {"checked": 0, "expired": 0, "revoked": 0}
        rows = self.repository.list()
        for row in rows:
            counts["checked"] += 1
            evidence = row.get("evidence")
            if isinstance(evidence, str):
                evidence = {}
            endpoint_key = row.get("endpoint_lookup_key") or (evidence or {}).get("endpoint_key")
            resolver_id_key = (evidence or {}).get("resolver_id_key")
            if not endpoint_key or not resolver_id_key:
                continue
            bound = registry.get_endpoint_binding(endpoint_key)
            anchor = registry.get_anchor(resolver_id_key)
            root_status = registry.get_root_status(row["state_root"])
            if root_status == "REVOKED" or (anchor and anchor.status == "REVOKED"):
                self.invalidate_cache_key(row["cache_key"], "REVOKED")
                counts["revoked"] += 1
                continue
            if bound != resolver_id_key or not anchor or anchor.object_version != row["object_version"] or anchor.object_hash != row["object_hash"] or anchor.state_root != row["state_root"]:
                self.invalidate_cache_key(row["cache_key"], "EXPIRED")
                counts["expired"] += 1
        return counts
