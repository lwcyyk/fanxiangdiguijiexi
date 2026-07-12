from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import time

from resolver_identity.db.repositories import AuditLogRepository, TrustedCacheRepository
from resolver_identity.verifier.cache_manager import CacheManager


@dataclass(slots=True)
class WatcherState:
    last_processed_block: int = 0
    last_seen_block_hash: str | None = None


class EventWatcher:
    """Idempotent registry event processor and Web3 log poller."""

    EVENT_NAMES = (
        "ResolverPublished",
        "ResolverUpdated",
        "ResolverRevoked",
        "RootRevoked",
        "EndpointBound",
        "EndpointUnbound",
    )

    def __init__(
        self,
        cache: CacheManager | TrustedCacheRepository,
        audit: AuditLogRepository | None = None,
        confirmations: int = 1,
        reorg_safety_blocks: int = 6,
        state: WatcherState | None = None,
        retry_count: int = 3,
        retry_delay_seconds: float = 0.25,
    ):
        if isinstance(cache, CacheManager):
            self.cache = cache
        else:
            self.cache = CacheManager(cache)
        self.audit = audit
        self.confirmations = confirmations
        self.reorg_safety_blocks = reorg_safety_blocks
        self.state = state or WatcherState()
        self.retry_count = retry_count
        self.retry_delay_seconds = retry_delay_seconds
        self._processed: set[tuple[str, int | None]] = set()

    def poll_web3_events(self, web3, contract, current_head: int | None = None) -> dict[str, int | bool]:
        """Poll confirmed contract logs and apply cache invalidations.

        This method is intended for short-lived invocations or an outer scheduler.
        It does not run forever, so tests and scripts can call it deterministically.
        """
        head = int(current_head if current_head is not None else web3.eth.block_number)
        to_block = head - self.confirmations
        if to_block < 0:
            return {"from_block": self.state.last_processed_block + 1, "to_block": to_block, "events": 0, "reorg": False}

        reorg = self._detect_reorg(web3)
        if reorg:
            expired = self.cache.expire_all("EXPIRED")
            self._audit("WatcherReorgCacheQuarantined", {"expired": expired})
            self.rollback_for_reorg(self.state.last_processed_block)

        from_block = self.state.last_processed_block + 1
        if to_block < from_block:
            return {"from_block": from_block, "to_block": to_block, "events": 0, "reorg": reorg}

        events: list[dict[str, Any]] = []
        for event_name in self.EVENT_NAMES:
            event_factory = getattr(contract.events, event_name)
            logs = self._get_logs_with_retry(event_factory, from_block, to_block)
            events.extend(self._normalize_web3_event(log) for log in logs)

        events.sort(key=lambda event: (int(event.get("blockNumber") or 0), int(event.get("logIndex") or 0), str(event.get("event"))))
        for event in events:
            self.handle_event(event)

        self.state.last_processed_block = max(self.state.last_processed_block, to_block)
        self.state.last_seen_block_hash = self._get_block_hash_with_retry(web3, to_block)
        return {"from_block": from_block, "to_block": to_block, "events": len(events), "reorg": reorg}

    def reconcile_registry_state(self, registry) -> dict[str, int]:
        """Poll current registry state to repair missed logs or watcher downtime."""
        counts = self.cache.refresh_registry_state(registry)
        self._audit("WatcherRegistryStateReconciled", counts)
        return counts

    def handle_event(self, event: dict[str, Any]) -> None:
        event_name = event.get("event") or event.get("event_type")
        block_number = event.get("blockNumber") or event.get("block_number")
        log_index = event.get("logIndex") or event.get("log_index")
        event_id = (str(event_name), int(block_number or 0) * 1_000_000 + int(log_index or 0))
        if event_id in self._processed:
            return
        self._processed.add(event_id)
        args = event.get("args") or event.get("payload") or {}

        if event_name == "ResolverRevoked":
            resolver_id = args.get("resolver_id") or args.get("resolverId")
            resolver_id_key = args.get("resolver_id_key") or args.get("resolverIdKey")
            if resolver_id:
                self.cache.invalidate_resolver(resolver_id, "REVOKED")
            elif resolver_id_key:
                self.cache.invalidate_resolver_key(resolver_id_key, "REVOKED")
                self._audit("WatcherResolverRevokedByKey", {"resolver_id_key": resolver_id_key})

        elif event_name == "RootRevoked":
            state_root = args.get("state_root") or args.get("stateRoot")
            if state_root:
                self.cache.invalidate_root(state_root, "REVOKED")

        elif event_name == "ResolverUpdated":
            resolver_id = args.get("resolver_id") or args.get("resolverId")
            resolver_id_key = args.get("resolver_id_key") or args.get("resolverIdKey")
            object_version = args.get("object_version") or args.get("objectVersion")
            if resolver_id and object_version is not None:
                self.cache.invalidate_object_version(resolver_id, int(object_version))
            elif resolver_id_key and object_version is not None:
                self.cache.invalidate_object_version_by_resolver_key(resolver_id_key, int(object_version))

        elif event_name == "EndpointUnbound":
            endpoint_key = args.get("endpoint_key") or args.get("endpointKey")
            endpoint = args.get("endpoint")
            if endpoint_key:
                self.cache.invalidate_endpoint_key(endpoint_key, "EXPIRED")
            elif endpoint:
                self.cache.invalidate_endpoint(endpoint, "EXPIRED")

        elif event_name == "EndpointBound":
            endpoint_key = args.get("endpoint_key") or args.get("endpointKey")
            if endpoint_key:
                self.cache.invalidate_endpoint_key(endpoint_key, "EXPIRED")
            self._audit("WatcherEndpointBoundRefreshNeeded", dict(args))

        elif event_name == "ResolverPublished":
            self._audit("WatcherResolverPublished", dict(args))

        if block_number is not None:
            self.state.last_processed_block = max(self.state.last_processed_block, int(block_number))
        self._audit(str(event_name), {"args": dict(args), "block_number": block_number, "log_index": log_index})

    def should_process_block(self, block_number: int, current_head: int) -> bool:
        return block_number <= current_head - self.confirmations

    def rollback_for_reorg(self, new_safe_block: int) -> None:
        self.state.last_processed_block = max(0, new_safe_block - self.reorg_safety_blocks)
        self.state.last_seen_block_hash = None
        self._processed.clear()
        self._audit("WatcherReorgRollback", {"last_processed_block": self.state.last_processed_block})

    def _detect_reorg(self, web3) -> bool:
        if self.state.last_processed_block <= 0 or not self.state.last_seen_block_hash:
            return False
        current_hash = self._get_block_hash_with_retry(web3, self.state.last_processed_block)
        return current_hash != self.state.last_seen_block_hash

    def _get_logs_with_retry(self, event_factory, from_block: int, to_block: int):
        last_exc = None
        for _ in range(self.retry_count):
            try:
                return event_factory().get_logs(from_block=from_block, to_block=to_block)
            except TypeError:
                try:
                    return event_factory().get_logs(fromBlock=from_block, toBlock=to_block)
                except Exception as exc:  # pragma: no cover - version-specific web3 path
                    last_exc = exc
            except Exception as exc:
                last_exc = exc
            time.sleep(self.retry_delay_seconds)
        raise RuntimeError(f"failed to poll registry events: {last_exc}")

    def _get_block_hash_with_retry(self, web3, block_number: int) -> str:
        last_exc = None
        for _ in range(self.retry_count):
            try:
                return self._normalize_hash(web3.eth.get_block(block_number)["hash"])
            except Exception as exc:
                last_exc = exc
                time.sleep(self.retry_delay_seconds)
        raise RuntimeError(f"failed to read block hash: {last_exc}")

    def _normalize_web3_event(self, event) -> dict[str, Any]:
        return {
            "event": event.get("event"),
            "args": {self._snake_or_original(key): self._normalize_value(value) for key, value in dict(event.get("args", {})).items()},
            "blockNumber": int(event.get("blockNumber", 0)),
            "logIndex": int(event.get("logIndex", 0)),
        }

    def _normalize_value(self, value):
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if hasattr(value, "hex") and value.__class__.__name__ in {"HexBytes", "HexBytes32"}:
            return value.hex()
        return value

    def _normalize_hash(self, value) -> str:
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if hasattr(value, "hex"):
            return value.hex()
        return str(value)

    def _snake_or_original(self, key: str) -> str:
        mapping = {
            "resolverIdKey": "resolver_id_key",
            "stateRoot": "state_root",
            "objectVersion": "object_version",
            "endpointKey": "endpoint_key",
        }
        return mapping.get(key, key)

    def _audit(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.record(event_type, payload)
