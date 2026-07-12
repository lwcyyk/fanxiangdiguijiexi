from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from resolver_identity.db.repositories import AuditLogRepository
from resolver_identity.db.schema import SCHEMA_VERSION, init_db
from resolver_identity.db.sqlite import connect


def require_database(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"database does not exist: {path}")


def integrity_result(conn: sqlite3.Connection) -> str:
    rows = conn.execute("PRAGMA integrity_check").fetchall()
    return "\n".join(str(row[0]) for row in rows)


def open_readonly(path: Path, *, immutable: bool = False) -> sqlite3.Connection:
    immutable_option = "&immutable=1" if immutable else ""
    conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro{immutable_option}", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def database_status(path: Path, *, immutable: bool = False) -> dict[str, object]:
    require_database(path)
    conn = open_readonly(path, immutable=immutable)
    try:
        return {
            "path": str(path.resolve()),
            "schema_version": int(conn.execute("PRAGMA user_version").fetchone()[0]),
            "supported_schema_version": SCHEMA_VERSION,
            "journal_mode": str(conn.execute("PRAGMA journal_mode").fetchone()[0]),
            "integrity": integrity_result(conn),
            "size_bytes": path.stat().st_size,
        }
    finally:
        conn.close()


def backup_database(source_path: Path, output_path: Path, force: bool) -> dict[str, object]:
    require_database(source_path)
    if output_path.exists() and not force:
        raise FileExistsError(f"backup already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp-{os.getpid()}")
    if temporary_path.exists():
        temporary_path.unlink()

    source = connect(source_path)
    destination = sqlite3.connect(temporary_path)
    try:
        source.backup(destination)
        destination.commit()
        destination.execute("PRAGMA journal_mode=DELETE")
        integrity = integrity_result(destination)
        if integrity != "ok":
            raise RuntimeError(f"backup integrity check failed: {integrity}")
    finally:
        destination.close()
        source.close()

    try:
        digest = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(output_path)
        return {
            "source": str(source_path.resolve()),
            "backup": str(output_path.resolve()),
            "size_bytes": output_path.stat().st_size,
            "sha256": digest,
            "integrity": "ok",
        }
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def check_watcher(path: Path, max_age_seconds: float) -> dict[str, object]:
    require_database(path)
    conn = open_readonly(path)
    try:
        row = conn.execute(
            "SELECT state_value FROM runtime_state WHERE state_key='watcher:last_success_epoch'"
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise RuntimeError("Watcher has not completed a successful synchronization cycle")
    age = time.time() - float(row[0])
    if age < 0 or age > max_age_seconds:
        raise RuntimeError(f"Watcher heartbeat is stale: age={age:.3f}s max={max_age_seconds:.3f}s")
    return {"ok": True, "heartbeat_age_seconds": round(age, 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolver Identity SQLite operations")
    parser.add_argument("--db", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("verify")
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--output", required=True, type=Path)
    backup_parser.add_argument("--force", action="store_true")
    prune_parser = subparsers.add_parser("prune-audit")
    prune_parser.add_argument("--retention-days", required=True, type=int)
    watcher_parser = subparsers.add_parser("check-watcher")
    watcher_parser.add_argument("--max-age", type=float, default=15.0)
    args = parser.parse_args()

    try:
        if args.command == "status":
            result = database_status(args.db)
        elif args.command == "verify":
            result = database_status(args.db, immutable=True)
            if result["integrity"] != "ok":
                raise RuntimeError(f"database integrity check failed: {result['integrity']}")
            if result["schema_version"] != SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema version {result['schema_version']} does not match {SCHEMA_VERSION}"
                )
        elif args.command == "backup":
            result = backup_database(args.db, args.output, args.force)
        elif args.command == "prune-audit":
            require_database(args.db)
            conn = connect(args.db)
            try:
                init_db(conn)
                result = {"deleted": AuditLogRepository(conn).purge_older_than_days(args.retention_days)}
            finally:
                conn.close()
        else:
            result = check_watcher(args.db, args.max_age)
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
