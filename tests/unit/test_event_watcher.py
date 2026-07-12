from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.chain.event_watcher import EventWatcher, WatcherState
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.resolver_verifier import ResolverVerifier


def publish_and_cache(stack):
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    assert stack.verifier.verify_endpoint(endpoint).accepted
    return obj, endpoint


def test_resolver_revoked_event_invalidates_cache_idempotently():
    stack = create_prototype_stack(signature_secret="secret")
    obj, endpoint = publish_and_cache(stack)
    watcher = EventWatcher(stack.cache)
    event = {"event": "ResolverRevoked", "args": {"resolver_id": obj.resolver_id}, "blockNumber": 10, "logIndex": 1}
    watcher.handle_event(event)
    watcher.handle_event(event)
    result = stack.verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["cache_revoked"]
    assert watcher.state.last_processed_block == 10


def test_root_revoked_event_invalidates_associated_cache():
    stack = create_prototype_stack(signature_secret="secret")
    obj, endpoint = publish_and_cache(stack)
    state_root = stack.indexer.get_resolver(obj.resolver_id)["state_root"]
    watcher = EventWatcher(stack.cache)
    watcher.handle_event({"event": "RootRevoked", "args": {"stateRoot": state_root}, "blockNumber": 11, "logIndex": 0})
    result = stack.verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["cache_revoked"]


def test_resolver_updated_event_expires_old_version_cache():
    stack = create_prototype_stack(signature_secret="secret")
    obj, endpoint = publish_and_cache(stack)
    watcher = EventWatcher(stack.cache)
    watcher.handle_event({"event": "ResolverUpdated", "args": {"resolver_id": obj.resolver_id, "objectVersion": 2}, "blockNumber": 12, "logIndex": 0})
    row = stack.trusted_cache_repository.list()[0]
    assert row["status"] == "EXPIRED"


def test_endpoint_unbound_event_expires_endpoint_cache():
    stack = create_prototype_stack(signature_secret="secret")
    _, endpoint = publish_and_cache(stack)
    endpoint_key = endpoint_lookup_key(endpoint)
    watcher = EventWatcher(stack.cache)
    watcher.handle_event({"event": "EndpointUnbound", "args": {"endpointKey": endpoint_key}, "blockNumber": 13, "logIndex": 0})
    row = stack.trusted_cache_repository.list()[0]
    assert row["status"] == "EXPIRED"


def test_endpoint_bound_event_expires_existing_endpoint_cache():
    stack = create_prototype_stack(signature_secret="secret")
    _, endpoint = publish_and_cache(stack)
    endpoint_key = endpoint_lookup_key(endpoint)
    watcher = EventWatcher(stack.cache)
    watcher.handle_event({"event": "EndpointBound", "args": {"endpointKey": endpoint_key}, "blockNumber": 14, "logIndex": 0})
    row = stack.trusted_cache_repository.list()[0]
    assert row["status"] == "EXPIRED"


def test_watcher_state_restore_and_reorg_rollback():
    state = WatcherState(last_processed_block=100)
    stack = create_prototype_stack(signature_secret="secret")
    watcher = EventWatcher(stack.cache, state=state, confirmations=2, reorg_safety_blocks=6)
    assert watcher.should_process_block(98, 100)
    assert not watcher.should_process_block(99, 100)
    watcher.rollback_for_reorg(120)
    assert watcher.state.last_processed_block == 114
    assert watcher.state.last_seen_block_hash is None


def test_poll_web3_events_orders_logs_tracks_state_and_invalidates_cache():
    stack = create_prototype_stack(signature_secret="secret")
    _, endpoint = publish_and_cache(stack)
    endpoint_key = endpoint_lookup_key(endpoint)
    watcher = EventWatcher(stack.cache, confirmations=1, state=WatcherState(last_processed_block=0))
    web3 = FakeWeb3(head=12, hashes={11: "0x" + "11" * 32})
    contract = FakeContract(
        {
            "EndpointUnbound": [FakeLog("EndpointUnbound", {"endpointKey": endpoint_key}, 11, 2)],
            "EndpointBound": [FakeLog("EndpointBound", {"endpointKey": endpoint_key}, 10, 1)],
        }
    )

    result = watcher.poll_web3_events(web3, contract)

    assert result == {"from_block": 1, "to_block": 11, "events": 2, "reorg": False}
    assert watcher.state.last_processed_block == 11
    assert watcher.state.last_seen_block_hash == "0x" + "11" * 32
    assert stack.trusted_cache_repository.list()[0]["status"] == "EXPIRED"
    assert contract.events.EndpointBound.calls == [(1, 11)]
    assert contract.events.EndpointUnbound.calls == [(1, 11)]


def test_poll_web3_events_retries_rpc_errors_then_succeeds():
    stack = create_prototype_stack(signature_secret="secret")
    _, endpoint = publish_and_cache(stack)
    endpoint_key = endpoint_lookup_key(endpoint)
    watcher = EventWatcher(stack.cache, confirmations=0, retry_count=2, retry_delay_seconds=0)
    web3 = FakeWeb3(head=5, hashes={5: "0x" + "05" * 32})
    contract = FakeContract({"EndpointUnbound": [FakeLog("EndpointUnbound", {"endpointKey": endpoint_key}, 5, 0)]}, failures={"EndpointUnbound": 1})

    result = watcher.poll_web3_events(web3, contract)

    assert result["events"] == 1
    assert stack.trusted_cache_repository.list()[0]["status"] == "EXPIRED"


def test_poll_web3_events_raises_after_rpc_retry_exhaustion():
    stack = create_prototype_stack(signature_secret="secret")
    publish_and_cache(stack)
    watcher = EventWatcher(stack.cache, confirmations=0, retry_count=2, retry_delay_seconds=0)
    web3 = FakeWeb3(head=5, hashes={5: "0x" + "05" * 32})
    contract = FakeContract({"EndpointUnbound": []}, failures={"EndpointUnbound": 3})

    try:
        watcher.poll_web3_events(web3, contract)
    except RuntimeError as exc:
        assert "failed to poll registry events" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


def test_poll_web3_events_rolls_back_on_reorg():
    stack = create_prototype_stack(signature_secret="secret")
    publish_and_cache(stack)
    watcher = EventWatcher(stack.cache, confirmations=0, reorg_safety_blocks=4, state=WatcherState(last_processed_block=10, last_seen_block_hash="0xold"))
    web3 = FakeWeb3(head=12, hashes={10: "0xnew", 12: "0x" + "12" * 32})
    contract = FakeContract({})

    result = watcher.poll_web3_events(web3, contract)

    assert result["reorg"] is True
    assert result["from_block"] == 7
    assert watcher.state.last_processed_block == 12
    assert stack.trusted_cache_repository.list()[0]["status"] == "EXPIRED"


def test_watcher_missed_event_can_be_repaired_by_registry_reconcile():
    stack = create_prototype_stack(signature_secret="secret")
    _, endpoint = publish_and_cache(stack)
    row = stack.trusted_cache_repository.list()[0]
    stack.registry.update_resolver(row["evidence"]["resolver_id_key"], "0x" + "ab" * 32, row["state_root"], 2, 9999999999, "ACTIVE")
    watcher = EventWatcher(stack.cache)

    refresh = watcher.reconcile_registry_state(stack.registry)

    assert refresh["expired"] == 1
    assert stack.trusted_cache_repository.list()[0]["status"] == "EXPIRED"


def test_temporary_registry_failure_fails_closed_without_cache():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    cache = CacheManager(stack.trusted_cache_repository)
    verifier = ResolverVerifier(stack.indexer, FailingRegistryBackend(), cache, VerificationPolicy.default(), "secret")

    result = verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))

    assert not result.accepted
    assert result.reasons == ["out_of_band_unavailable"]
    assert "temporary RPC failure" in result.evidence["error"]


class FailingRegistryBackend:
    def get_endpoint_binding(self, endpoint_key):
        raise RuntimeError("temporary RPC failure")

    lookup_resolver_by_endpoint = get_endpoint_binding

    def get_anchor(self, resolver_id_key):
        raise RuntimeError("temporary RPC failure")

    get_resolver_anchor = get_anchor

    def get_root_status(self, state_root):
        raise RuntimeError("temporary RPC failure")


class FakeLog:
    def __init__(self, event, args, block_number, log_index):
        self.data = {"event": event, "args": args, "blockNumber": block_number, "logIndex": log_index}

    def get(self, key, default=None):
        return self.data.get(key, default)


class FakeEventSource:
    def __init__(self, name, logs, failures=0):
        self.name = name
        self.logs = logs
        self.failures = failures
        self.calls = []

    def __call__(self):
        return self

    def get_logs(self, from_block=None, to_block=None, fromBlock=None, toBlock=None):
        start = from_block if from_block is not None else fromBlock
        end = to_block if to_block is not None else toBlock
        self.calls.append((start, end))
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError(f"temporary {self.name} RPC error")
        return [log for log in self.logs if start <= log.get("blockNumber") <= end]


class FakeEvents:
    def __init__(self, logs_by_event, failures):
        for name in EventWatcher.EVENT_NAMES:
            setattr(self, name, FakeEventSource(name, logs_by_event.get(name, []), failures.get(name, 0)))


class FakeContract:
    def __init__(self, logs_by_event, failures=None):
        self.events = FakeEvents(logs_by_event, failures or {})


class FakeEth:
    def __init__(self, head, hashes):
        self.block_number = head
        self.hashes = hashes

    def get_block(self, block_number):
        return {"hash": self.hashes[block_number]}


class FakeWeb3:
    def __init__(self, head, hashes):
        self.eth = FakeEth(head, hashes)
