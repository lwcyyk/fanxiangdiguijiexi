from __future__ import annotations

import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect an EVM Registry deployment and print its pinned identity")
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--contract-address", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    from web3 import Web3

    web3 = Web3(Web3.HTTPProvider(args.rpc_url, request_kwargs={"timeout": args.timeout}))
    if not web3.is_address(args.contract_address):
        raise SystemExit("invalid contract address")
    code = web3.eth.get_code(args.contract_address)
    if not code:
        raise SystemExit("contract address has no code")
    code_hash = Web3.keccak(code).hex()
    if not code_hash.startswith("0x"):
        code_hash = "0x" + code_hash
    print(json.dumps({
        "chain_id": int(web3.eth.chain_id),
        "contract_address": web3.to_checksum_address(args.contract_address),
        "contract_code_hash": code_hash.lower(),
        "latest_block": int(web3.eth.block_number),
    }, indent=2))


if __name__ == "__main__":
    main()
