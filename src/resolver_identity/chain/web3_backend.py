from __future__ import annotations

import os
from threading import Lock
from dataclasses import dataclass
from typing import Any

from resolver_identity.chain.backend import (
    ResolverAnchor,
    RootRecord,
    bytes32_to_bytes,
    decode_anchor,
    decode_status,
    encode_status,
    normalize_bytes32,
)


class Web3RegistryError(RuntimeError):
    pass


@dataclass(slots=True)
class Web3RegistryConfig:
    rpc_url: str
    contract_address: str
    chain_id: int
    abi: list[dict[str, Any]]
    private_key_env: str | None = None
    private_key_file: str | None = None
    sender_address: str | None = None
    expected_code_hash: str | None = None
    request_timeout_seconds: float = 5.0
    transaction_timeout_seconds: float = 120.0


class Web3RegistryBackend:
    """Real Solidity registry adapter.

    The optional web3 dependency is imported at runtime so SQLite-only tests and
    minimal environments continue to work. Private keys are read only from the
    configured environment variable and are never logged by this class.
    """

    def __init__(self, config: Web3RegistryConfig):
        try:
            from web3 import Web3
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional package
            raise Web3RegistryError("web3 package is required for Web3RegistryBackend") from exc
        self.Web3 = Web3
        self.config = config
        self.web3 = Web3(Web3.HTTPProvider(config.rpc_url, request_kwargs={"timeout": config.request_timeout_seconds}))
        actual_chain_id = int(self.web3.eth.chain_id)
        if actual_chain_id != int(config.chain_id):
            raise Web3RegistryError(f"chain_id mismatch: expected {config.chain_id}, got {actual_chain_id}")
        if not self.web3.is_address(config.contract_address):
            raise Web3RegistryError("invalid contract address")
        code = self.web3.eth.get_code(config.contract_address)
        if not code:
            raise Web3RegistryError("contract address has no code")
        actual_code_hash = normalize_hex_hash(Web3.keccak(code).hex())
        if config.expected_code_hash and actual_code_hash != normalize_hex_hash(config.expected_code_hash):
            raise Web3RegistryError(f"contract code hash mismatch: expected {config.expected_code_hash}, got {actual_code_hash}")
        self.contract_code_hash = actual_code_hash
        self.contract = self.web3.eth.contract(address=self.web3.to_checksum_address(config.contract_address), abi=config.abi)
        self._tx_lock = Lock()

    def get_anchor(self, resolver_id_key: str) -> ResolverAnchor | None:
        return self.get_resolver_anchor(resolver_id_key)

    def get_resolver_anchor(self, resolver_id_key: str) -> ResolverAnchor | None:
        raw = self.contract.functions.getResolverAnchor(bytes32_to_bytes(resolver_id_key)).call()
        return decode_anchor(raw)

    def get_root_status(self, state_root: str) -> str | None:
        return decode_status(self.contract.functions.getRootStatus(bytes32_to_bytes(state_root)).call())

    def get_root_record(self, state_root: str) -> RootRecord | None:
        raw = self.contract.functions.getRootRecord(bytes32_to_bytes(state_root)).call()
        normalized_root = normalize_bytes32(raw[0])
        if int(normalized_root, 16) == 0:
            return None
        return RootRecord(
            state_root=normalized_root,
            status=decode_status(raw[1]),
            published_at=int(raw[2]),
            version=int(raw[3]),
        )

    def get_endpoint_binding(self, endpoint_key: str) -> str | None:
        value = self.contract.functions.lookupResolverByEndpoint(bytes32_to_bytes(endpoint_key)).call()
        normalized = normalize_bytes32(value)
        return None if int(normalized, 16) == 0 else normalized

    def lookup_resolver_by_endpoint(self, endpoint_key: str) -> str | None:
        return self.get_endpoint_binding(endpoint_key)

    def publish_root(self, state_root: str, status: str = "ACTIVE", version: int = 1) -> None:
        if status.upper() != "ACTIVE":
            raise Web3RegistryError("publish_root only supports ACTIVE; use revoke_root for revocation")
        self._transact(self.contract.functions.publishRoot(bytes32_to_bytes(state_root), int(version)))

    def revoke_root(self, state_root: str) -> None:
        self._transact(self.contract.functions.revokeRoot(bytes32_to_bytes(state_root)))

    def publish_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None:
        self._transact(self.contract.functions.publishResolver(
            bytes32_to_bytes(resolver_id_key),
            bytes32_to_bytes(object_hash),
            bytes32_to_bytes(state_root),
            int(object_version),
            int(valid_until),
            encode_status(status),
        ))

    def update_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None:
        self._transact(self.contract.functions.updateResolver(
            bytes32_to_bytes(resolver_id_key),
            bytes32_to_bytes(object_hash),
            bytes32_to_bytes(state_root),
            int(object_version),
            int(valid_until),
            encode_status(status),
        ))

    def revoke_resolver(self, resolver_id_key: str) -> None:
        self._transact(self.contract.functions.revokeResolver(bytes32_to_bytes(resolver_id_key)))

    def bind_endpoint(self, endpoint_key: str, resolver_id_key: str) -> None:
        self._transact(self.contract.functions.bindEndpoint(bytes32_to_bytes(endpoint_key), bytes32_to_bytes(resolver_id_key)))

    def unbind_endpoint(self, endpoint_key: str) -> None:
        self._transact(self.contract.functions.unbindEndpoint(bytes32_to_bytes(endpoint_key)))

    def _account(self):
        private_key = None
        if self.config.private_key_file:
            from pathlib import Path

            private_key = Path(self.config.private_key_file).read_text(encoding="utf-8").strip()
        elif self.config.private_key_env:
            private_key = os.environ.get(self.config.private_key_env)
        if not private_key:
            raise Web3RegistryError("write operation requires a private key file or environment variable")
        return self.web3.eth.account.from_key(private_key)

    def _transact(self, function) -> dict[str, Any]:
        lock = getattr(self, "_tx_lock", None)
        if lock is None:
            lock = self._tx_lock = Lock()
        with lock:
            return self._transact_locked(function)

    def _transact_locked(self, function) -> dict[str, Any]:
        if self.config.sender_address and not self.config.private_key_env and not self.config.private_key_file:
            tx_hash = function.transact({"from": self.web3.to_checksum_address(self.config.sender_address)})
            receipt = self._wait_for_receipt(tx_hash)
            if int(receipt.get("status", 0)) != 1:
                raise Web3RegistryError("transaction receipt status != 1")
            return dict(receipt)
        account = self._account()
        tx = function.build_transaction({
            "from": account.address,
            "nonce": self.web3.eth.get_transaction_count(account.address),
            "chainId": self.config.chain_id,
        })
        signed = account.sign_transaction(tx)
        raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
        tx_hash = self.web3.eth.send_raw_transaction(raw_tx)
        receipt = self._wait_for_receipt(tx_hash)
        if int(receipt.get("status", 0)) != 1:
            raise Web3RegistryError("transaction receipt status != 1")
        return dict(receipt)

    def _wait_for_receipt(self, tx_hash):
        try:
            return self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.config.transaction_timeout_seconds)
        except TypeError:  # compatibility with lightweight test doubles
            return self.web3.eth.wait_for_transaction_receipt(tx_hash)


def normalize_hex_hash(value: str) -> str:
    value = str(value).lower()
    return value if value.startswith("0x") else "0x" + value
