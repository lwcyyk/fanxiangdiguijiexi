import os

from resolver_identity.chain.backend import decode_anchor, decode_status, encode_status, normalize_bytes32
from resolver_identity.chain.web3_backend import Web3RegistryBackend, Web3RegistryConfig, Web3RegistryError


def test_bytes32_and_status_conversion():
    value = "0x" + "ab" * 32
    assert normalize_bytes32(value.upper()) == value
    assert decode_status(1) == "ACTIVE"
    assert decode_status("revoked") == "REVOKED"
    assert encode_status("ACTIVE") == 1


def test_anchor_decoding():
    raw = (
        bytes.fromhex("11" * 32),
        bytes.fromhex("22" * 32),
        bytes.fromhex("33" * 32),
        7,
        999,
        1,
    )
    anchor = decode_anchor(raw)
    assert anchor.resolver_id_key == "0x" + "11" * 32
    assert anchor.object_hash == "0x" + "22" * 32
    assert anchor.state_root == "0x" + "33" * 32
    assert anchor.object_version == 7
    assert anchor.valid_until == 999
    assert anchor.status == "ACTIVE"


def test_zero_anchor_decodes_to_none():
    raw = (bytes(32), bytes(32), bytes(32), 0, 0, 0)
    assert decode_anchor(raw) is None


def test_web3_receipt_status_failure_raises():
    backend = Web3RegistryBackend.__new__(Web3RegistryBackend)
    backend.config = Web3RegistryConfig("http://127.0.0.1:8545", "0x" + "11" * 20, 31337, [], private_key_env="TEST_WEB3_PK")
    backend.web3 = FakeWeb3()
    os.environ["TEST_WEB3_PK"] = "0x" + "01" * 32
    try:
        try:
            backend._transact(FakeFunction())
        except Web3RegistryError as exc:
            assert "receipt status" in str(exc)
        else:
            raise AssertionError("expected Web3RegistryError")
    finally:
        os.environ.pop("TEST_WEB3_PK", None)


class FakeFunction:
    def build_transaction(self, params):
        return {"from": params["from"], "nonce": params["nonce"], "chainId": params["chainId"]}


class FakeSigned:
    rawTransaction = b"signed"


class FakeAccount:
    address = "0x0000000000000000000000000000000000000001"

    def sign_transaction(self, tx):
        return FakeSigned()


class FakeAccountFactory:
    def from_key(self, private_key):
        return FakeAccount()


class FakeEth:
    account = FakeAccountFactory()

    def get_transaction_count(self, address):
        return 0

    def send_raw_transaction(self, raw):
        return b"hash"

    def wait_for_transaction_receipt(self, tx_hash):
        return {"status": 0}


class FakeWeb3:
    eth = FakeEth()
