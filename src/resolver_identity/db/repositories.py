from __future__ import annotations

from functools import wraps
import json
import sqlite3
from threading import Lock, RLock
from typing import Any

from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.models.authenticity_object import ResolverAuthenticityObjectV1
from resolver_identity.models.endpoint import ResolverEndpoint


_connection_locks: dict[int, RLock] = {}
_connection_locks_guard = Lock()


def _lock_for_connection(conn: sqlite3.Connection) -> RLock:
    key = id(conn)
    with _connection_locks_guard:
        return _connection_locks.setdefault(key, RLock())


def _serialized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._connection_lock:
            return method(self, *args, **kwargs)

    return wrapped


def _serialize_repository(repository_type):
    for name, method in vars(repository_type).items():
        if not name.startswith("_") and callable(method):
            setattr(repository_type, name, _serialized(method))
    return repository_type


class _SQLiteRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._connection_lock = _lock_for_connection(conn)


@_serialize_repository
class AuditLogRepository(_SQLiteRepository):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__(conn)

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO audit_logs(event_type,payload_json) VALUES(?,?)",
            (event_type, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        self.conn.commit()

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        rows = self.conn.execute(
            "SELECT id,event_type,payload_json,created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["payload"] = json.loads(data.pop("payload_json"))
            out.append(data)
        return out

    def purge_older_than_days(self, days: int) -> int:
        if days < 1:
            raise ValueError("audit retention must be at least one day")
        cursor = self.conn.execute(
            "DELETE FROM audit_logs WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        self.conn.commit()
        return cursor.rowcount


@_serialize_repository
class IndexerRepository(_SQLiteRepository):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__(conn)
        self.audit = AuditLogRepository(conn)

    def upsert_resolver_object(self, obj: ResolverAuthenticityObjectV1, object_hash: str, state_root: str) -> None:
        rid_key = resolver_id_key(obj.resolver_id)
        self.conn.execute(
            """INSERT INTO resolver_objects(resolver_id,resolver_id_key,object_json,object_hash,object_version,status,valid_from,valid_until,state_root,issuer,key_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(resolver_id) DO UPDATE SET resolver_id_key=excluded.resolver_id_key, object_json=excluded.object_json,
               object_hash=excluded.object_hash, object_version=excluded.object_version, status=excluded.status,
               valid_from=excluded.valid_from, valid_until=excluded.valid_until, state_root=excluded.state_root,
               issuer=excluded.issuer, key_id=excluded.key_id, updated_at=CURRENT_TIMESTAMP""",
            (obj.resolver_id, rid_key, json.dumps(obj.to_dict(), ensure_ascii=False), object_hash, obj.object_version, obj.status, obj.valid_from, obj.valid_until, state_root, obj.issuer, obj.key_id),
        )
        self.conn.commit()
        self.audit.record("IndexerResolverObjectUpserted", {"resolver_id": obj.resolver_id, "resolver_id_key": rid_key, "object_hash": object_hash, "object_version": obj.object_version, "status": obj.status, "state_root": state_root})

    def replace_endpoints(self, resolver_id: str, endpoints: list[tuple[ResolverEndpoint, str]]) -> None:
        self.conn.execute("DELETE FROM resolver_endpoints WHERE resolver_id=?", (resolver_id,))
        for endpoint, endpoint_key in endpoints:
            self.conn.execute(
                "INSERT OR REPLACE INTO resolver_endpoints(resolver_id,endpoint_json,endpoint_key) VALUES(?,?,?)",
                (resolver_id, json.dumps(endpoint.normalized().to_dict(), ensure_ascii=False), endpoint_key),
            )
        self.conn.commit()
        self.audit.record("IndexerEndpointsReplaced", {"resolver_id": resolver_id, "endpoint_keys": [key for _, key in endpoints]})

    def put_lookup(self, lookup_key: str, resolver_id: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO resolver_lookup_index(lookup_key,resolver_id_key,resolver_id) VALUES(?,?,?)",
            (lookup_key, resolver_id_key(resolver_id), resolver_id),
        )
        self.conn.commit()

    def delete_lookup(self, lookup_key: str, resolver_id: str | None = None) -> None:
        if resolver_id is None:
            self.conn.execute("DELETE FROM resolver_lookup_index WHERE lookup_key=?", (lookup_key,))
        else:
            self.conn.execute("DELETE FROM resolver_lookup_index WHERE lookup_key=? AND resolver_id=?", (lookup_key, resolver_id))
        self.conn.commit()

    def publish_root(self, state_root: str, status: str = "ACTIVE") -> None:
        self.conn.execute("INSERT OR REPLACE INTO state_roots(state_root,status) VALUES(?,?)", (state_root, status))
        self.conn.commit()
        self.audit.record("IndexerRootPublished", {"state_root": state_root, "status": status})

    def put_proof(self, resolver_id: str, leaf_hash: str, proof: dict[str, Any], state_root: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO resolver_proofs(resolver_id,leaf_hash,proof_json,state_root) VALUES(?,?,?,?)",
            (resolver_id, leaf_hash, json.dumps(proof, ensure_ascii=False, sort_keys=True), state_root),
        )
        self.conn.commit()
        self.audit.record("IndexerProofStored", {"resolver_id": resolver_id, "leaf_hash": leaf_hash, "state_root": state_root})

    def get_proof(self, resolver_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM resolver_proofs WHERE resolver_id=?", (resolver_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["proof"] = json.loads(data.pop("proof_json"))
        return data

    def lookup(self, lookup_key: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM resolver_lookup_index WHERE lookup_key=?", (lookup_key,)).fetchone()
        return dict(row) if row else None

    def get_resolver(self, resolver_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM resolver_objects WHERE resolver_id=?", (resolver_id,)).fetchone()
        return dict(row) if row else None

    def list_endpoint_keys(self, resolver_id: str) -> list[str]:
        rows = self.conn.execute("SELECT endpoint_key FROM resolver_endpoints WHERE resolver_id=?", (resolver_id,)).fetchall()
        return [row["endpoint_key"] for row in rows]

    def get_root(self, state_root: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM state_roots WHERE state_root=?", (state_root,)).fetchone()
        return dict(row) if row else None


@_serialize_repository
class TrustedCacheRepository(_SQLiteRepository):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__(conn)
        self.audit = AuditLogRepository(conn)

    def put(self, cache_key: str, row: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO trusted_cache(cache_key,endpoint_lookup_key,resolver_id,endpoint_json,object_hash,object_version,state_root,status,verified_at,soft_expire_at,hard_expire_at,evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cache_key, row["endpoint_lookup_key"], row["resolver_id"], json.dumps(row["endpoint"], ensure_ascii=False), row["object_hash"], row["object_version"],
                row["state_root"], row["status"], row["verified_at"], row["soft_expire_at"], row["hard_expire_at"], json.dumps(row.get("evidence", {}), ensure_ascii=False),
            ),
        )
        self.conn.commit()

    def put_if_generation(self, cache_key: str, row: dict[str, Any], expected_generation: int) -> bool:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            current = self.current_generation()
            if current != expected_generation:
                self.conn.rollback()
                return False
            self.conn.execute(
                """INSERT OR REPLACE INTO trusted_cache(cache_key,endpoint_lookup_key,resolver_id,endpoint_json,object_hash,object_version,state_root,status,verified_at,soft_expire_at,hard_expire_at,evidence_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cache_key, row["endpoint_lookup_key"], row["resolver_id"], json.dumps(row["endpoint"], ensure_ascii=False), row["object_hash"], row["object_version"],
                    row["state_root"], row["status"], row["verified_at"], row["soft_expire_at"], row["hard_expire_at"], json.dumps(row.get("evidence", {}), ensure_ascii=False),
                ),
            )
            self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            raise

    def current_generation(self) -> int:
        row = self.conn.execute("SELECT state_value FROM runtime_state WHERE state_key='cache_generation'").fetchone()
        return int(row["state_value"]) if row else 0

    def bump_generation(self) -> int:
        self.conn.execute(
            """INSERT INTO runtime_state(state_key,state_value) VALUES('cache_generation','1')
               ON CONFLICT(state_key) DO UPDATE SET state_value=CAST(CAST(state_value AS INTEGER)+1 AS TEXT), updated_at=CURRENT_TIMESTAMP"""
        )
        self.conn.commit()
        return self.current_generation()

    def get(self, cache_key: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM trusted_cache WHERE cache_key=?", (cache_key,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["endpoint"] = json.loads(data.pop("endpoint_json"))
        data["evidence"] = json.loads(data.pop("evidence_json"))
        return data

    def get_by_endpoint_lookup_key(self, endpoint_lookup_key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM trusted_cache WHERE endpoint_lookup_key=? ORDER BY verified_at DESC LIMIT 1",
            (endpoint_lookup_key,),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["endpoint"] = json.loads(data.pop("endpoint_json"))
        data["evidence"] = json.loads(data.pop("evidence_json"))
        return data

    def update_status(self, cache_key: str, status: str) -> None:
        self.conn.execute("UPDATE trusted_cache SET status=? WHERE cache_key=?", (status, cache_key))
        self.conn.commit()
        self.audit.record("TrustedCacheStatusUpdated", {"cache_key": cache_key, "status": status})

    def mark_status_by_resolver(self, resolver_id: str, status: str) -> None:
        self.conn.execute("UPDATE trusted_cache SET status=? WHERE resolver_id=?", (status, resolver_id))
        self.conn.commit()
        self.audit.record("TrustedCacheStatusMarked", {"resolver_id": resolver_id, "status": status})

    def mark_status_by_root(self, state_root: str, status: str) -> None:
        self.conn.execute("UPDATE trusted_cache SET status=? WHERE state_root=?", (status, state_root))
        self.conn.commit()
        self.audit.record("TrustedCacheRootStatusMarked", {"state_root": state_root, "status": status})

    def mark_stale_versions(self, resolver_id: str, object_version: int) -> None:
        self.conn.execute("UPDATE trusted_cache SET status='EXPIRED' WHERE resolver_id=? AND object_version != ?", (resolver_id, object_version))
        self.conn.commit()
        self.audit.record("TrustedCacheStaleVersionsExpired", {"resolver_id": resolver_id, "object_version": object_version})

    def list(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM trusted_cache ORDER BY verified_at DESC").fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["endpoint"] = json.loads(data.pop("endpoint_json"))
            data["evidence"] = json.loads(data.pop("evidence_json"))
            out.append(data)
        return out


@_serialize_repository
class RegistryRepository(_SQLiteRepository):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__(conn)
        self.audit = AuditLogRepository(conn)

    def publish_anchor(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str) -> None:
        existing = self.get_anchor(resolver_id_key)
        self.conn.execute(
            "INSERT OR REPLACE INTO registry_anchors(resolver_id_key,object_hash,state_root,object_version,valid_until,status) VALUES(?,?,?,?,?,?)",
            (resolver_id_key, object_hash, state_root, object_version, valid_until, status),
        )
        self.conn.commit()
        self.audit.record("ResolverUpdated" if existing else "ResolverPublished", {"resolver_id_key": resolver_id_key, "object_hash": object_hash, "state_root": state_root, "object_version": object_version, "valid_until": valid_until, "status": status})

    def get_anchor(self, resolver_id_key: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM registry_anchors WHERE resolver_id_key=?", (resolver_id_key,)).fetchone()
        return dict(row) if row else None

    def bind_endpoint(self, endpoint_key: str, resolver_id_key: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO registry_endpoint_bindings(endpoint_key,resolver_id_key) VALUES(?,?)", (endpoint_key, resolver_id_key))
        self.conn.commit()
        self.audit.record("EndpointBound", {"endpoint_key": endpoint_key, "resolver_id_key": resolver_id_key})

    def unbind_endpoint(self, endpoint_key: str) -> None:
        resolver_id_key = self.get_endpoint_binding(endpoint_key)
        self.conn.execute("DELETE FROM registry_endpoint_bindings WHERE endpoint_key=?", (endpoint_key,))
        self.conn.commit()
        self.audit.record("EndpointUnbound", {"endpoint_key": endpoint_key, "resolver_id_key": resolver_id_key})

    def get_endpoint_binding(self, endpoint_key: str) -> str | None:
        row = self.conn.execute("SELECT resolver_id_key FROM registry_endpoint_bindings WHERE endpoint_key=?", (endpoint_key,)).fetchone()
        return row["resolver_id_key"] if row else None

    def publish_root(self, state_root: str, status: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO registry_roots(state_root,status) VALUES(?,?)", (state_root, status))
        self.conn.commit()
        self.audit.record("RootPublished" if status == "ACTIVE" else "RootRevoked", {"state_root": state_root, "status": status})

    def get_root_status(self, state_root: str) -> str | None:
        row = self.conn.execute("SELECT status FROM registry_roots WHERE state_root=?", (state_root,)).fetchone()
        return row["status"] if row else None

    def revoke_resolver(self, resolver_id_key: str) -> None:
        self.conn.execute("UPDATE registry_anchors SET status='REVOKED' WHERE resolver_id_key=?", (resolver_id_key,))
        self.conn.commit()
        self.audit.record("ResolverRevoked", {"resolver_id_key": resolver_id_key})


@_serialize_repository
class RuntimeStateRepository(_SQLiteRepository):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__(conn)

    def get(self, key: str) -> str | None:
        row = self.conn.execute("SELECT state_value FROM runtime_state WHERE state_key=?", (key,)).fetchone()
        return row["state_value"] if row else None

    def set(self, key: str, value: str | int) -> None:
        self.conn.execute(
            """INSERT INTO runtime_state(state_key,state_value) VALUES(?,?)
               ON CONFLICT(state_key) DO UPDATE SET state_value=excluded.state_value, updated_at=CURRENT_TIMESTAMP""",
            (key, str(value)),
        )
        self.conn.commit()

    def delete(self, key: str) -> None:
        self.conn.execute("DELETE FROM runtime_state WHERE state_key=?", (key,))
        self.conn.commit()
