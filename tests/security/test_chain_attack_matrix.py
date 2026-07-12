from __future__ import annotations

import copy

import pytest

from resolver_identity.agent.verification_chain import VerificationChain, sign_verification_chain, verify_verification_chain_payload
from resolver_identity.crypto.signatures import generate_ed25519_keypair
from resolver_identity.models.endpoint import ResolverEndpoint

from tests.integration.test_agent_resolver_chain import (
    R1_AGENT_PRIVATE,
    R1_AGENT_PUBLIC,
    assert_servfail,
    base_distributed_payloads,
    run_distributed_payload,
    sign_existing_chain,
)


@pytest.mark.parametrize("attack", ["orphan", "splice-resolver", "splice-endpoint", "duplicate-downstream"])
async def test_downstream_chain_splice_attacks_fail_closed(attack):
    _stack, payload, _ = base_distributed_payloads()
    if attack == "orphan":
        payload["hops"] = []
    elif attack == "splice-resolver":
        payload["downstream_chains"][0]["resolver_id"] = "operator-a/r3"
    elif attack == "splice-endpoint":
        payload["downstream_chains"][0]["endpoint"] = {"ip": "192.0.2.99", "port": 53, "transport": "udp"}
    else:
        payload["downstream_chains"].append(copy.deepcopy(payload["downstream_chains"][0]))
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


async def test_accepted_agent_capable_hop_cannot_omit_middle_chain():
    _stack, payload, _ = base_distributed_payloads()
    payload["downstream_chains"] = []
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


async def test_terminal_boundary_cannot_overlap_recursive_hop():
    _stack, payload, _ = base_distributed_payloads()
    payload["terminal_upstreams"] = [copy.deepcopy(payload["hops"][0]["upstream_endpoint"])]
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


@pytest.mark.parametrize("field,value", [("final_result", True), ("chain_errors", ["ignored failure"])])
async def test_inconsistent_final_result_or_chain_errors_fail_closed(field, value):
    _stack, payload, _ = base_distributed_payloads()
    if field == "final_result":
        payload["hops"][0]["accepted"] = False
        payload["hops"][0]["status"] = "REJECTED"
        payload["hops"][0]["reasons"] = ["forced"]
        payload["final_result"] = value
    else:
        payload[field] = value
        payload["final_result"] = True
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


async def test_agent_key_substitution_with_unauthorized_key_fails_closed():
    _stack, payload, _ = base_distributed_payloads()
    attacker_private, attacker_public = generate_ed25519_keypair()
    payload["hops"][0]["evidence"]["agent_public_key"] = attacker_public
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)
    downstream = VerificationChain.from_dict(payload["downstream_chains"][0])
    payload["downstream_chains"][0] = sign_verification_chain(downstream, attacker_private)
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


async def test_valid_r3_chain_cannot_be_attached_directly_under_r1():
    _stack, payload, _ = base_distributed_payloads()
    r3_chain = payload["downstream_chains"][0]["downstream_chains"][0]
    payload["downstream_chains"] = [copy.deepcopy(r3_chain)]
    payload = sign_existing_chain(payload, R1_AGENT_PRIVATE)

    result = await run_distributed_payload(payload)

    assert_servfail(result)


def test_request_challenge_prevents_exact_chain_reuse():
    chain = VerificationChain(
        resolver_id="operator-a/r1",
        endpoint=ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"),
        config_version="1",
        challenge="challenge-a-012345678901234567890123",
        final_result=True,
    )
    payload = sign_verification_chain(chain, R1_AGENT_PRIVATE)

    verified = verify_verification_chain_payload(payload, R1_AGENT_PUBLIC, expected_challenge=chain.challenge)
    assert verified.final_result
    with pytest.raises(ValueError, match="challenge mismatch"):
        verify_verification_chain_payload(payload, R1_AGENT_PUBLIC, expected_challenge="challenge-b-012345678901234567890123")
