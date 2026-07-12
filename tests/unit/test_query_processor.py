from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.wrapper.query_processor import UpstreamResolver

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
PRIMARY_RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
FALLBACK_RESPONSE = bytes.fromhex("123481800001000000000000") + b"\x07example\x03net\x00\x00\x01\x00\x01"


def publish(stack, ip):
    obj = build_resolver_object(
        f"operator-a/resolver-{ip.split('.')[-1]}",
        "operator-a",
        "Operator A",
        [{"ip": ip, "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    return obj


async def test_processor_uses_fallback_when_primary_unverified():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, "192.0.2.54")
    calls = []

    async def forwarder(query, host, port):
        calls.append(host)
        return PRIMARY_RESPONSE if host == "192.0.2.53" else FALLBACK_RESPONSE

    result = await stack.processor.process(
        QUERY,
        [UpstreamResolver("192.0.2.53"), UpstreamResolver("192.0.2.54")],
        forwarder,
    )
    assert result.accepted
    assert result.upstream.ip == "192.0.2.54"
    assert result.response == FALLBACK_RESPONSE
    assert calls == ["192.0.2.53", "192.0.2.54"]


async def test_processor_returns_servfail_when_all_upstreams_fail_verification():
    stack = create_prototype_stack(signature_secret="secret")

    async def forwarder(query, host, port):
        return PRIMARY_RESPONSE

    result = await stack.processor.process(QUERY, [UpstreamResolver("192.0.2.53")], forwarder)
    assert not result.accepted
    assert result.response[3] & 0x0F == 2


async def test_processor_skips_forward_errors_and_tries_fallback():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, "192.0.2.54")

    async def forwarder(query, host, port):
        if host == "192.0.2.53":
            raise TimeoutError("primary timeout")
        return FALLBACK_RESPONSE

    result = await stack.processor.process(
        QUERY,
        [UpstreamResolver("192.0.2.53"), UpstreamResolver("192.0.2.54")],
        forwarder,
    )
    assert result.accepted
    assert result.upstream.ip == "192.0.2.54"


async def test_processor_accepts_only_when_all_observed_resolvers_verify():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, "192.0.2.53")
    publish(stack, "192.0.2.54")

    async def forwarder(query, host, port):
        return PRIMARY_RESPONSE

    result = await stack.processor.process(
        QUERY,
        [UpstreamResolver("192.0.2.53", observed_resolvers=[ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp")])],
        forwarder,
    )
    assert result.accepted
    entry = stack.journal.get(result.request_id)
    path_event = [event for event in entry["events"] if event["event"] == "path_verification"][0]
    assert len(path_event["results"]) == 2
    assert all(item["accepted"] for item in path_event["results"])


async def test_processor_rejects_path_when_any_observed_resolver_fails():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack, "192.0.2.53")

    async def forwarder(query, host, port):
        return PRIMARY_RESPONSE

    result = await stack.processor.process(
        QUERY,
        [UpstreamResolver("192.0.2.53", observed_resolvers=[ResolverEndpoint(ip="192.0.2.55", port=53, transport="udp")])],
        forwarder,
    )
    assert not result.accepted
    assert result.response[3] & 0x0F == 2
