from __future__ import annotations

from pathlib import Path

from resolver_identity.chain.contract_loader import load_contract_abi
from resolver_identity.chain.registry_client import SQLiteRegistryClient
from resolver_identity.chain.web3_backend import Web3RegistryBackend, Web3RegistryConfig
from resolver_identity.common.config import Settings
from resolver_identity.db.repositories import RegistryRepository


def create_registry_backend(settings: Settings, registry_repository: RegistryRepository):
    if settings.registry_mode.lower() == "web3":
        if not settings.web3_rpc_url or not settings.web3_contract_address:
            raise ValueError("web3 registry mode requires RPC URL and contract address")
        abi = load_contract_abi(Path(settings.web3_abi_path))
        return Web3RegistryBackend(
            Web3RegistryConfig(
                rpc_url=settings.web3_rpc_url,
                contract_address=settings.web3_contract_address,
                chain_id=settings.web3_chain_id,
                abi=abi,
                private_key_env=settings.web3_private_key_env or None,
                private_key_file=settings.web3_private_key_file or None,
                sender_address=settings.web3_sender_address or None,
                expected_code_hash=settings.web3_contract_code_hash or None,
                request_timeout_seconds=settings.web3_request_timeout_seconds,
                transaction_timeout_seconds=settings.web3_transaction_timeout_seconds,
            )
        )
    return SQLiteRegistryClient(registry_repository)
