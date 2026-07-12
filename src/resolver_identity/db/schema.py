from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS resolver_objects (
  resolver_id TEXT PRIMARY KEY,
  resolver_id_key TEXT NOT NULL UNIQUE,
  object_json TEXT NOT NULL,
  object_hash TEXT NOT NULL,
  object_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  state_root TEXT NOT NULL,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS resolver_endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  resolver_id TEXT NOT NULL,
  endpoint_json TEXT NOT NULL,
  endpoint_key TEXT NOT NULL UNIQUE,
  FOREIGN KEY(resolver_id) REFERENCES resolver_objects(resolver_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS resolver_lookup_index (
  lookup_key TEXT PRIMARY KEY,
  resolver_id_key TEXT NOT NULL,
  resolver_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolver_proofs (
  resolver_id TEXT PRIMARY KEY,
  leaf_hash TEXT NOT NULL,
  proof_json TEXT NOT NULL,
  state_root TEXT NOT NULL,
  FOREIGN KEY(resolver_id) REFERENCES resolver_objects(resolver_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS resolver_revocations (
  resolver_id TEXT PRIMARY KEY,
  reason TEXT,
  revoked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS state_roots (
  state_root TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS trusted_cache (
  cache_key TEXT PRIMARY KEY,
  endpoint_lookup_key TEXT NOT NULL,
  resolver_id TEXT NOT NULL,
  endpoint_json TEXT NOT NULL,
  object_hash TEXT NOT NULL,
  object_version INTEGER NOT NULL,
  state_root TEXT NOT NULL,
  status TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  soft_expire_at TEXT NOT NULL,
  hard_expire_at TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registry_anchors (
  resolver_id_key TEXT PRIMARY KEY,
  object_hash TEXT NOT NULL,
  state_root TEXT NOT NULL,
  object_version INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registry_endpoint_bindings (
  endpoint_key TEXT PRIMARY KEY,
  resolver_id_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registry_roots (
  state_root TEXT PRIMARY KEY,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_state (
  state_key TEXT PRIMARY KEY,
  state_value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db(conn: sqlite3.Connection) -> None:
    current_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current_version > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
        )
    conn.executescript(SCHEMA)
    if current_version < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.commit()
