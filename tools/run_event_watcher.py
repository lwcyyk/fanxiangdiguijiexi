from __future__ import annotations

import argparse
import time

from resolver_identity.chain.event_watcher import EventWatcher, WatcherState
from resolver_identity.common.config import load_settings
from resolver_identity.common.registry_factory import create_registry_backend
from resolver_identity.db.repositories import AuditLogRepository, RegistryRepository, RuntimeStateRepository, TrustedCacheRepository
from resolver_identity.db.schema import init_db
from resolver_identity.db.sqlite import connect


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Run local registry event/cache watcher")
    parser.add_argument("--db", default=settings.db_path)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    conn = connect(args.db)
    init_db(conn)
    runtime_state = RuntimeStateRepository(conn)
    last_block = int(runtime_state.get("watcher:last_processed_block") or 0)
    last_hash = runtime_state.get("watcher:last_seen_block_hash")
    watcher = EventWatcher(
        TrustedCacheRepository(conn),
        audit=AuditLogRepository(conn),
        confirmations=settings.watcher_confirmations,
        state=WatcherState(last_processed_block=last_block, last_seen_block_hash=last_hash),
    )
    registry = create_registry_backend(settings, RegistryRepository(conn))
    while True:
        if hasattr(registry, "web3") and hasattr(registry, "contract"):
            watcher.poll_web3_events(registry.web3, registry.contract)
        watcher.reconcile_registry_state(registry)
        runtime_state.set("watcher:last_processed_block", watcher.state.last_processed_block)
        if watcher.state.last_seen_block_hash:
            runtime_state.set("watcher:last_seen_block_hash", watcher.state.last_seen_block_hash)
        else:
            runtime_state.delete("watcher:last_seen_block_hash")
        runtime_state.set("watcher:last_success_epoch", f"{time.time():.6f}")
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
