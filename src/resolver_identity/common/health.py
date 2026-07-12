from __future__ import annotations

import sqlite3
from typing import Any

from resolver_identity.db.schema import SCHEMA_VERSION


def probe_database(conn: sqlite3.Connection) -> dict[str, int | bool]:
    conn.execute("SELECT 1").fetchone()
    schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if schema_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {schema_version} does not match supported version {SCHEMA_VERSION}"
        )
    return {"ok": True, "schema_version": schema_version}


def probe_registry(registry: Any) -> dict[str, Any]:
    web3 = getattr(registry, "web3", None)
    if web3 is None:
        return {"ok": True, "mode": "sqlite"}
    config = registry.config
    chain_id = int(web3.eth.chain_id)
    if chain_id != int(config.chain_id):
        raise RuntimeError("Registry chain ID changed")
    latest_block = int(web3.eth.block_number)
    code = web3.eth.get_code(config.contract_address)
    if not code:
        raise RuntimeError("Registry contract has no runtime code")
    actual_hash = registry.Web3.keccak(code).hex().lower()
    if not actual_hash.startswith("0x"):
        actual_hash = "0x" + actual_hash
    if actual_hash != registry.contract_code_hash:
        raise RuntimeError("Registry contract runtime code hash changed")
    return {
        "ok": True,
        "mode": "web3",
        "chain_id": chain_id,
        "latest_block": latest_block,
        "contract_code_hash": actual_hash,
    }
