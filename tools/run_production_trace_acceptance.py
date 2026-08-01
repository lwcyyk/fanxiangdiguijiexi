#!/usr/bin/env python3
"""Run the production Trace acceptance against real Knot DNS processes.

This harness never synthesizes Trace events. It launches the patched Knot
Resolver, a DNSSEC-signing Knot authoritative server, and the repository's
Rust data plane, then derives the acceptance record from observed results.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener


REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "rust"
TARGET = RUST / "target" / "debug"
SCHEMA_VERSION = "resolver-identity-production-trace-acceptance-v1"
RELEASE_VERSION = "0.3.0-norn-knot-rc1"
RESOLVER_NAME = "Knot Resolver"
RESOLVER_VERSION = "6.3.0"
RESOLVER_COMMIT = "124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e"
TRACE_PRODUCER_VERSION = "0.2.0"


class AcceptanceError(RuntimeError):
    pass


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    log_handle: Any


class Lab:
    def __init__(self, root: Path, library_path: str) -> None:
        self.root = root
        self.library_path = library_path
        self.processes: dict[str, ManagedProcess] = {}
        self.logs = root / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)

    def environment(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        environment.pop("HTTP_PROXY", None)
        environment.pop("HTTPS_PROXY", None)
        environment.pop("ALL_PROXY", None)
        environment.pop("http_proxy", None)
        environment.pop("https_proxy", None)
        environment.pop("all_proxy", None)
        environment["NO_PROXY"] = "127.0.0.1,127.0.0.2,localhost"
        if self.library_path:
            environment["LD_LIBRARY_PATH"] = self.library_path
        if extra:
            environment.update(extra)
        return environment

    def start(
        self,
        name: str,
        command: list[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> None:
        self.stop(name)
        log_handle = (self.logs / f"{name}.log").open("ab")
        process = subprocess.Popen(
            command,
            cwd=cwd or REPO,
            env=self.environment(environment),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.processes[name] = ManagedProcess(name, process, log_handle)

    def stop(self, name: str) -> None:
        managed = self.processes.pop(name, None)
        if managed is None:
            return
        if managed.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(managed.process.pid, signal.SIGTERM)
            try:
                managed.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(managed.process.pid, signal.SIGKILL)
                managed.process.wait(timeout=5)
        managed.log_handle.close()

    def assert_running(self, name: str) -> None:
        managed = self.processes.get(name)
        if managed is None or managed.process.poll() is not None:
            log = (self.logs / f"{name}.log").read_text(errors="replace")
            raise AcceptanceError(f"{name} exited unexpectedly:\n{log[-4000:]}")

    def diagnostic_summary(self) -> str:
        """Return bounded child-process diagnostics before temporary files are removed."""
        sections: list[str] = []
        for path in sorted(self.logs.glob("*.log")):
            managed = self.processes.get(path.stem)
            status = "stopped"
            if managed is not None:
                return_code = managed.process.poll()
                status = "running" if return_code is None else f"exit={return_code}"
            content = path.read_text(errors="replace")
            sections.append(f"--- {path.name} ({status}) ---\n{content[-4000:]}")
        return "\n".join(sections)

    def close(self) -> None:
        for name in list(reversed(self.processes)):
            self.stop(name)


class EndpointFailureGate:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._armed = False
        self._failed_bind: tuple[str, int] | None = None
        self.triggered = threading.Event()

    def arm(self) -> None:
        with self._lock:
            self._armed = True

    def should_drop(self, bind: tuple[str, int]) -> bool:
        with self._lock:
            if not self._armed:
                return False
            if self._failed_bind is None:
                self._failed_bind = bind
                self.triggered.set()
            return self._failed_bind == bind


class UdpDnsProxy:
    def __init__(
        self,
        bind: tuple[str, int],
        upstream: tuple[str, int],
        response_delay: float = 0.0,
        failure_gate: EndpointFailureGate | None = None,
    ) -> None:
        self.bind = bind
        self.upstream = upstream
        self.response_delay = response_delay
        self.failure_gate = failure_gate
        self.stopping = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0.1)
        self.socket.bind(bind)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stopping.set()
        self.socket.close()
        self.thread.join(timeout=2)

    def _serve(self) -> None:
        while not self.stopping.is_set():
            try:
                query, client = self.socket.recvfrom(65_535)
            except (OSError, TimeoutError):
                continue
            if self.failure_gate is not None and self.failure_gate.should_drop(self.bind):
                continue
            try:
                response = exchange_udp(self.upstream, query, timeout=2)
                if self.response_delay:
                    time.sleep(self.response_delay)
                self.socket.sendto(response, client)
            except (OSError, TimeoutError):
                continue


def run(
    command: list[str],
    *,
    cwd: Path = REPO,
    environment: dict[str, str] | None = None,
    timeout: int = 300,
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AcceptanceError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def wait_for(predicate: Any, description: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (ConnectionError, OSError):
            pass
        time.sleep(0.05)
    raise AcceptanceError(f"timed out waiting for {description}")


def wait_socket(path: Path) -> None:
    wait_for(lambda: path.is_socket(), f"Unix socket {path}")


def wait_http(url: str, expected: int = 204) -> None:
    opener = build_opener(ProxyHandler({}))

    def ready() -> bool:
        try:
            response = opener.open(url, timeout=0.5)
            return response.status == expected
        except Exception:
            return False

    wait_for(ready, url)


def http_status(url: str) -> int:
    try:
        with build_opener(ProxyHandler({})).open(url, timeout=1) as response:
            return response.status
    except HTTPError as error:
        return error.code


def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"


def dns_query(name: str, transaction_id: int, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + encode_name(
        name
    ) + struct.pack("!HH", qtype, 1)


def exchange_udp(address: tuple[str, int], query: bytes, timeout: float = 5.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, address)
        return client.recvfrom(65535)[0]


def exchange_tcp(address: tuple[str, int], query: bytes, timeout: float = 5.0) -> bytes:
    with socket.create_connection(address, timeout=timeout) as client:
        client.sendall(struct.pack("!H", len(query)) + query)
        length = recv_exact(client, 2)
        return recv_exact(client, struct.unpack("!H", length)[0])


def recv_exact(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise AcceptanceError("DNS TCP peer closed before the full frame arrived")
        chunks.extend(chunk)
    return bytes(chunks)


def rcode(response: bytes) -> int:
    if len(response) < 12:
        raise AcceptanceError("DNS response is shorter than the header")
    return response[3] & 0x0F


def write_authority_files(root: Path) -> tuple[Path, Path]:
    authority = root / "authority"
    for path in (authority / "run", authority / "storage", authority / "keys"):
        path.mkdir(parents=True, exist_ok=True)
    zone = authority / "storage" / "root.zone"
    large = " ".join(f'"{chr(65 + index) * 190}"' for index in range(10))
    zone.write_text(
        "\n".join(
            [
                "$ORIGIN .",
                "$TTL 60",
                "@ IN SOA a.root.lab. hostmaster.root.lab. (1 60 60 3600 60)",
                "@ IN NS a.root.lab.",
                "a.root.lab. IN A 127.0.0.2",
                "target.trace.ri. IN A 203.0.113.80",
                "alias.trace.ri. IN CNAME target.trace.ri.",
                "udp.trace.ri. IN A 203.0.113.81",
                "tcp.trace.ri. IN A 203.0.113.82",
                "cache.trace.ri. IN A 203.0.113.83",
                "parallel.trace.ri. IN A 203.0.113.84",
                "agent-down.trace.ri. IN A 203.0.113.85",
                "stale.trace.ri. IN A 203.0.113.86",
                "revoked.trace.ri. IN A 203.0.113.87",
                "orphan.trace.ri. IN A 203.0.113.94",
                "producer-down.trace.ri. IN A 203.0.113.88",
                "queue-full.trace.ri. IN A 203.0.113.93",
                "restart.trace.ri. IN A 203.0.113.89",
                "restart-ok.trace.ri. IN A 203.0.113.90",
                "warm.failover.trace.ri. IN A 203.0.113.91",
                "switch.failover.trace.ri. IN A 203.0.113.92",
                f"large.trace.ri. IN TXT {large}",
                "",
            ]
        )
    )
    config = authority / "knot.conf"
    config.write_text(
        f"""server:
    rundir: {authority / 'run'}
    listen: 127.0.0.2@15353

database:
    storage: {authority / 'storage'}

keystore:
  - id: trace-keys
    backend: pem
    config: {authority / 'keys'}

policy:
  - id: trace-policy
    keystore: trace-keys
    algorithm: ecdsap256sha256
    ksk-shared: off

template:
  - id: trace-template
    storage: {authority / 'storage'}
    file: root.zone
    dnssec-signing: on
    dnssec-policy: trace-policy

zone:
  - domain: .
    template: trace-template
"""
    )
    return config, zone


def discover_trust_anchor(kdig: Path, lab: Lab) -> str:
    output = run(
        [
            str(kdig),
            "@127.0.0.2",
            "-p",
            "15353",
            ".",
            "DNSKEY",
            "+dnssec",
            "+short",
        ],
        environment=lab.environment(),
    )
    for line in output.splitlines():
        if line.startswith("257 "):
            return f". 60 IN DNSKEY {line}\n"
    raise AcceptanceError(f"Knot authoritative root returned no KSK:\n{output}")


def write_resolver_config(
    root: Path,
    trust_anchor: str,
    *,
    targets: tuple[str, ...] = ("127.0.0.2@15353",),
    filename: str = "kresd.conf",
) -> Path:
    config = root / filename
    anchor = trust_anchor.strip().replace("'", "\\'")
    target_value = (
        f"'{targets[0]}'"
        if len(targets) == 1
        else "{" + ",".join(f"'{target}'" for target in targets) + "}"
    )
    config.write_text(
        f"""net.listen('127.0.0.1', 15354, {{ kind = 'dns' }})
cache.size = 20 * MB
trust_anchors.remove('.')
if ta_update then modules.unload('ta_update') end
if ta_signal_query then modules.unload('ta_signal_query') end
if priming then modules.unload('priming') end
trust_anchors.add('{anchor}')
policy.add(policy.all(policy.FORWARD({target_value})))
"""
    )
    return config


def rust_binaries() -> dict[str, Path]:
    return {
        "agent": TARGET / "ri-agent",
        "adapter": TARGET / "ri-trace-adapter",
        "producer": TARGET / "ri-knot-trace-producer",
        "wrapper": TARGET / "ri-wrapper",
    }


def seed_lab(root: Path) -> Path:
    seed = root / "seed"
    run(
        [
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            "ri-knot-trace-producer",
            "--example",
            "seed_real_resolver_lab",
            "--",
            str(seed),
        ],
        cwd=RUST,
    )
    return seed


def service_environments(root: Path, seed: Path) -> dict[str, dict[str, str]]:
    sockets = root / "sockets"
    sockets.mkdir(parents=True, exist_ok=True)
    database = seed / "evidence-v2.db"
    common = {
        "RI_ENVIRONMENT": "test",
        "RI_DATABASE": str(database),
    }
    return {
        "agent": {
            **common,
            "RI_VERIFICATION_MODE": "public-hybrid",
            "RI_AGENT_BIND": "127.0.0.1:18443",
            "RI_AGENT_SERVER_ID": "operator/L01/r1",
            "RI_AGENT_KEY_ID": "lab-agent-key",
            "RI_AGENT_PRIVATE_KEY_FILE": str(seed / "agent_private_key"),
            "RI_TRACE_INGEST_TOKEN_FILE": str(seed / "trace_ingest_token"),
            "RI_AGENT_WRAPPER_TOKEN_FILE": str(seed / "agent_wrapper_token"),
            "RI_AGENT_PEER_TOKEN_FILE": str(seed / "agent_peer_token"),
            "RI_ISSUER_KEYS_FILE": str(seed / "issuer-keys.json"),
            "RI_AGENT_MAX_AGE_SECONDS": "60",
            "RI_TRACE_WAIT_MILLIS": "5000",
            "RI_REGISTRY_MAX_STALENESS_SECONDS": "300",
            "RI_TRACE_RETENTION_SECONDS": "3600",
        },
        "adapter": {
            **common,
            "RI_TRACE_SOCKET": str(sockets / "events.sock"),
            "RI_TRACE_SOCKET_MODE": "0600",
            "RI_TRACE_PRODUCER_UID": str(os.getuid()),
            "RI_TRACE_SPOOL_DATABASE": str(root / "trace-spool.db"),
            "RI_TRACE_QUEUE_CAPACITY": "4096",
            "RI_TRACE_BATCH_SIZE": "64",
            "RI_TRACE_SPOOL_MAX_EVENTS": "100000",
            "RI_TRACE_AGENT_URL": "http://127.0.0.1:18443",
            "RI_TRACE_INGEST_TOKEN_FILE": str(seed / "trace_ingest_token"),
            "RI_TRACE_MONITORING_BIND": "127.0.0.1:19110",
        },
        "producer": {
            "RI_KNOT_TRACE_HOOK_SOCKET": str(sockets / "knot-hook.sock"),
            "RI_KNOT_TRACE_HOOK_SOCKET_MODE": "0600",
            "RI_KNOT_TRACE_EXPECTED_UID": str(os.getuid()),
            "RI_TRACE_SOCKET": str(sockets / "events.sock"),
            "RI_AGENT_SERVER_ID": "operator/L01/r1",
            "RI_TRACE_MAX_CONTEXTS": "65536",
            "RI_TRACE_ACK_TIMEOUT_MS": "1000",
        },
        "resolver": {
            "RI_KNOT_TRACE_HOOK_SOCKET": str(sockets / "knot-hook.sock"),
            "RI_TRACE_ACK_TIMEOUT_MS": "1000",
        },
        "wrapper": {
            **common,
            "RI_VERIFICATION_MODE": "public-hybrid",
            "RI_ISSUER_KEYS_FILE": str(seed / "issuer-keys.json"),
            "RI_WRAPPER_UDP_BIND": "127.0.0.1:15355",
            "RI_WRAPPER_TCP_BIND": "127.0.0.1:15355",
            "RI_WRAPPER_MONITORING_BIND": "127.0.0.1:19108",
            "RI_WRAPPER_AGENT_URL": "http://127.0.0.1:18443",
            "RI_WRAPPER_AGENT_TOKEN_FILE": str(seed / "agent_wrapper_token"),
            # One TCP hop gives each Wrapper request one complete Resolver Trace;
            # Knot still exercises UDP, retries, and TCP fallback upstream.
            "RI_WRAPPER_UPSTREAMS": "tcp://127.0.0.1:15354",
            "RI_WRAPPER_UPSTREAM_TIMEOUT_MS": "15000",
            "RI_WRAPPER_AGENT_TIMEOUT_MS": "7500",
            "RI_WRAPPER_TRANSACTION_ID_REUSE_DELAY_MS": "5000",
            "RI_WRAPPER_MAX_INFLIGHT": "2048",
            "RI_WRAPPER_MAX_CONCURRENT_VERIFICATIONS": "32",
            "RI_REGISTRY_MAX_STALENESS_SECONDS": "300",
        },
    }


def start_data_plane(
    lab: Lab,
    binaries: dict[str, Path],
    environments: dict[str, dict[str, str]],
    kresd: Path,
    kresd_config: Path,
) -> None:
    cache = lab.root / "cache"
    cache.mkdir(exist_ok=True)
    lab.start("agent", [str(binaries["agent"])], environment=environments["agent"])
    wait_http("http://127.0.0.1:18443/readyz", expected=200)
    lab.start(
        "adapter", [str(binaries["adapter"])], environment=environments["adapter"]
    )
    wait_socket(Path(environments["adapter"]["RI_TRACE_SOCKET"]))
    lab.start(
        "producer", [str(binaries["producer"])], environment=environments["producer"]
    )
    wait_socket(Path(environments["producer"]["RI_KNOT_TRACE_HOOK_SOCKET"]))
    lab.start(
        "resolver",
        [str(kresd), "-n", "-v", "-c", str(kresd_config), str(cache)],
        environment=environments["resolver"],
    )
    wait_for(
        lambda: tcp_connectable(("127.0.0.1", 15354)),
        "real Knot Resolver",
    )
    lab.start(
        "wrapper", [str(binaries["wrapper"])], environment=environments["wrapper"]
    )
    wait_http("http://127.0.0.1:19108/readyz")


def check_success(response: bytes, name: str) -> None:
    if rcode(response) != 0:
        raise AcceptanceError(f"{name} returned DNS rcode {rcode(response)}, expected NOERROR")


def tcp_connectable(address: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(address, timeout=0.2):
            return True
    except OSError:
        return False


def check_servfail(response: bytes, name: str) -> None:
    if rcode(response) != 2:
        raise AcceptanceError(f"{name} returned DNS rcode {rcode(response)}, expected SERVFAIL")


def sqlite_value(database: Path, query: str, parameters: tuple[Any, ...] = ()) -> Any:
    with sqlite3.connect(database) as connection:
        row = connection.execute(query, parameters).fetchone()
    if row is None:
        raise AcceptanceError(f"SQLite query returned no rows: {query}")
    return row[0]


def sqlite_table_exists(database: Path, table: str) -> bool:
    if not database.is_file():
        return False
    try:
        with sqlite3.connect(database) as connection:
            return (
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()[0]
                == 1
            )
    except sqlite3.Error:
        return False


def test_real_queries(
    database: Path, concurrency: int
) -> tuple[dict[str, str], int, int]:
    results: dict[str, str] = {}
    udp = exchange_udp(("127.0.0.1", 15355), dns_query("udp.trace.ri", 0x1001))
    check_success(udp, "UDP query")
    results["udp_query"] = "passed"

    tcp = exchange_tcp(("127.0.0.1", 15355), dns_query("tcp.trace.ri", 0x1002))
    check_success(tcp, "TCP query")
    results["tcp_query"] = "passed"

    cname = exchange_udp(("127.0.0.1", 15355), dns_query("alias.trace.ri", 0x1003))
    check_success(cname, "CNAME query")
    results["cname_resolution"] = "passed"

    transport_switches_before = sqlite_value(
        database,
        "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='TRANSPORT_SWITCH'",
    )
    large = exchange_udp(
        ("127.0.0.1", 15355), dns_query("large.trace.ri", 0x1006, qtype=16), timeout=15
    )
    check_success(large, "large UDP query with TCP fallback")
    wait_for(
        lambda: sqlite_value(
            database,
            "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='TRANSPORT_SWITCH'",
        )
        > transport_switches_before,
        "Knot UDP-to-TCP transport switch Trace",
    )
    results["udp_to_tcp_fallback"] = "passed"

    first = exchange_udp(("127.0.0.1", 15355), dns_query("cache.trace.ri", 0x1004))
    second = exchange_udp(("127.0.0.1", 15355), dns_query("cache.trace.ri", 0x1005))
    check_success(first, "cold-cache query")
    check_success(second, "hot-cache query")
    cache_hits = sqlite_value(
        database,
        "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='CACHE_HIT'",
    )
    if cache_hits < 1:
        raise AcceptanceError("real Resolver did not emit a CacheHit event")
    results["cache_hit"] = "passed"

    same_name = "parallel.trace.ri"
    warm_parallel = exchange_udp(
        ("127.0.0.1", 15355), dns_query(same_name, 0x1FFF), timeout=10
    )
    check_success(warm_parallel, "same-qname concurrency cache warmup")

    def concurrent_query(index: int) -> bytes:
        return exchange_udp(
            ("127.0.0.1", 15355),
            dns_query(same_name, 0x2000 + (index % 8)),
            timeout=10,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, 64)) as pool:
        responses = list(pool.map(concurrent_query, range(concurrency)))
    for response in responses:
        check_success(response, "concurrent same-qname query")
    results["same_qname_concurrency"] = "passed"
    results["transaction_id_reuse"] = "passed"

    cross_talk = sqlite_value(
        database,
        """SELECT COUNT(*)
           FROM ri_v2_trace_event_claims c
           JOIN ri_v2_trace_events e ON e.event_id=c.event_id
           JOIN ri_v2_query_contexts q ON q.request_trace_id=c.request_trace_id
           WHERE json_extract(e.event_json,'$.correlation_id') <> q.correlation_id""",
    )
    duplicate_claims = sqlite_value(
        database,
        """SELECT COUNT(*) FROM (
             SELECT event_id,COUNT(*) AS count FROM ri_v2_trace_event_claims
             GROUP BY event_id HAVING count > 1
           )""",
    )
    cross_talk += duplicate_claims
    if cross_talk != 0:
        raise AcceptanceError(f"detected {cross_talk} cross-query Trace claims")
    return results, concurrency, cross_talk


def test_multi_upstream_failover(
    lab: Lab,
    database: Path,
    kresd: Path,
    direct_config: Path,
    trust_anchor: str,
    resolver_environment: dict[str, str],
) -> dict[str, str]:
    failure_gate = EndpointFailureGate()
    proxies = {
        "127.0.0.3": UdpDnsProxy(
            ("127.0.0.3", 15353),
            ("127.0.0.2", 15353),
            failure_gate=failure_gate,
        ),
        "127.0.0.4": UdpDnsProxy(
            ("127.0.0.4", 15353),
            ("127.0.0.2", 15353),
            response_delay=0.03,
            failure_gate=failure_gate,
        ),
    }
    for proxy in proxies.values():
        proxy.start()
    failover_config = write_resolver_config(
        lab.root,
        trust_anchor,
        targets=("127.0.0.3@15353", "127.0.0.4@15353"),
        filename="kresd-failover.conf",
    )
    failover_cache = lab.root / "cache-failover"
    failover_cache.mkdir(exist_ok=True)
    try:
        lab.start(
            "resolver",
            [str(kresd), "-n", "-v", "-c", str(failover_config), str(failover_cache)],
            environment=resolver_environment,
        )
        wait_for(
            lambda: tcp_connectable(("127.0.0.1", 15354)),
            "Knot Resolver with two real upstream endpoints",
        )
        warm = exchange_udp(
            ("127.0.0.1", 15355), dns_query("warm.failover.trace.ri", 0x4101), timeout=15
        )
        check_success(warm, "multi-upstream warm query")
        timeouts_before = sqlite_value(
            database,
            "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='UPSTREAM_TIMEOUT'",
        )
        switches_before = sqlite_value(
            database,
            "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='TRANSPORT_SWITCH'",
        )
        # Whichever endpoint Knot selects first is disabled from its first packet
        # onward. The other endpoint remains healthy, so a successful answer
        # proves an actual timeout and cross-endpoint retry rather than relying on
        # probabilistic resolver selection from the warm-up request.
        failure_gate.arm()
        switched = exchange_udp(
            ("127.0.0.1", 15355),
            dns_query("switch.failover.trace.ri", 0x4102),
            timeout=30,
        )
        check_success(switched, "multi-upstream failover query")
        if not failure_gate.triggered.wait(timeout=1):
            raise AcceptanceError("deterministic upstream failure gate was not exercised")
        wait_for(
            lambda: sqlite_value(
                database,
                "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='UPSTREAM_TIMEOUT'",
            )
            > timeouts_before,
            "Knot upstream timeout Trace",
            timeout=10,
        )
        wait_for(
            lambda: sqlite_value(
                database,
                "SELECT COUNT(*) FROM ri_v2_trace_events WHERE json_extract(event_json,'$.kind')='TRANSPORT_SWITCH'",
            )
            > switches_before,
            "Knot multi-upstream switch Trace",
            timeout=10,
        )
        return {
            "udp_timeout_retry": "passed",
            "multi_upstream_failover": "passed",
        }
    finally:
        for proxy in proxies.values():
            proxy.stop()
        direct_cache = lab.root / "cache-after-failover"
        direct_cache.mkdir(exist_ok=True)
        lab.start(
            "resolver",
            [str(kresd), "-n", "-v", "-c", str(direct_config), str(direct_cache)],
            environment=resolver_environment,
        )
        wait_for(
            lambda: rcode(
                exchange_udp(("127.0.0.1", 15354), dns_query("restart.trace.ri", 10))
            )
            == 0,
            "Knot Resolver after failover test",
        )


def direct_adapter_mutation_test(adapter_socket: Path, spool_database: Path) -> None:
    with sqlite3.connect(spool_database) as connection:
        row = connection.execute(
            "SELECT event_json FROM trace_spool_seen ORDER BY created_at LIMIT 1"
        ).fetchone()
    if row is None:
        raise AcceptanceError("Trace Adapter spool contains no durable seen event")
    event = json.loads(row[0])
    event["observed_at"] += 1
    payload = json.dumps(event, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(adapter_socket))
        client.sendall(b"RI-TRACE/2\n" + payload)
        acknowledgement = client.recv(256)
    if acknowledgement.startswith(b"OK "):
        raise AcceptanceError("Trace Adapter accepted a modified duplicate event")


def run_negative_tests(
    lab: Lab,
    binaries: dict[str, Path],
    environments: dict[str, dict[str, str]],
    kresd: Path,
    kresd_config: Path,
    database: Path,
) -> dict[str, str]:
    results: dict[str, str] = {}
    lab.stop("resolver")
    cache = lab.root / "cache"
    lab.start(
        "resolver",
        [str(kresd), "-n", "-v", "-c", str(kresd_config), str(cache)],
        environment=environments["resolver"],
    )
    wait_for(
        lambda: rcode(
            exchange_udp(("127.0.0.1", 15354), dns_query("restart.trace.ri", 9))
        )
        == 0,
        "restarted Knot Resolver",
    )
    restored = exchange_udp(
        ("127.0.0.1", 15355), dns_query("restart-ok.trace.ri", 0x3005)
    )
    check_success(restored, "Resolver restart test")
    results["resolver_restart"] = "passed"

    adapter_socket = Path(environments["adapter"]["RI_TRACE_SOCKET"])
    direct_adapter_mutation_test(adapter_socket, Path(environments["adapter"]["RI_TRACE_SPOOL_DATABASE"]))
    results["modified_trace_rejected"] = "passed"

    direct = exchange_tcp(
        ("127.0.0.1", 15354), dns_query("orphan.trace.ri", 0x3010), timeout=10
    )
    check_success(direct, "unregistered Resolver cache seed")
    orphan = exchange_udp(
        ("127.0.0.1", 15355), dns_query("orphan.trace.ri", 0x3011), timeout=10
    )
    check_servfail(orphan, "orphan cache provenance test")

    lab.stop("agent")
    failed = exchange_udp(("127.0.0.1", 15355), dns_query("agent-down.trace.ri", 0x3001))
    check_servfail(failed, "Agent unavailable test")
    results["agent_unavailable_fail_closed"] = "passed"
    lab.start("agent", [str(binaries["agent"])], environment=environments["agent"])
    wait_http("http://127.0.0.1:18443/readyz", expected=200)

    with sqlite3.connect(database) as connection:
        old_epoch = connection.execute(
            "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_last_success_epoch'"
        ).fetchone()[0]
        connection.execute(
            "UPDATE ri_v2_meta SET meta_value='1' WHERE meta_key='registry_last_success_epoch'"
        )
    failed = exchange_udp(("127.0.0.1", 15355), dns_query("stale.trace.ri", 0x3002))
    check_servfail(failed, "stale Registry snapshot test")
    results["stale_registry_fail_closed"] = "passed"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ri_v2_meta SET meta_value=? WHERE meta_key='registry_last_success_epoch'",
            (old_epoch,),
        )

    with sqlite3.connect(database) as connection:
        old_registry = connection.execute(
            "SELECT registry_json FROM ri_v2_identities WHERE server_id='authority/trace-root'"
        ).fetchone()[0]
        revoked = json.loads(old_registry)
        revoked["resolver_status"] = "REVOKED"
        connection.execute(
            "UPDATE ri_v2_identities SET registry_json=? WHERE server_id='authority/trace-root'",
            (json.dumps(revoked, separators=(",", ":")),),
        )
    failed = exchange_udp(("127.0.0.1", 15355), dns_query("revoked.trace.ri", 0x3003))
    check_servfail(failed, "revoked identity test")
    results["invalid_identity_fail_closed"] = "passed"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ri_v2_identities SET registry_json=? WHERE server_id='authority/trace-root'",
            (old_registry,),
        )

    spool_database = Path(environments["adapter"]["RI_TRACE_SPOOL_DATABASE"])
    wait_for(
        lambda: sqlite_value(spool_database, "SELECT COUNT(*) FROM trace_spool") == 0,
        "orphan cache traces to leave the active spool",
        timeout=20,
    )
    dead_letters = sqlite_value(
        spool_database, "SELECT COUNT(*) FROM trace_dead_letter"
    )
    if dead_letters < 1:
        raise AcceptanceError("orphan cache Trace was not isolated in dead-letter storage")
    results["orphan_cache_trace_fail_closed"] = "passed"

    lab.stop("resolver")
    lab.stop("producer")
    lab.stop("adapter")
    lab.stop("agent")
    queue_environment = dict(environments["adapter"])
    queue_database = lab.root / "queue-full-spool.db"
    queue_environment["RI_TRACE_SPOOL_DATABASE"] = str(queue_database)
    queue_environment["RI_TRACE_SPOOL_MAX_EVENTS"] = "1"
    lab.start("adapter", [str(binaries["adapter"])], environment=queue_environment)
    wait_http("http://127.0.0.1:19110/healthz")
    wait_for(
        lambda: sqlite_table_exists(queue_database, "trace_spool"),
        "queue-full Trace spool schema",
    )
    lab.start(
        "producer", [str(binaries["producer"])], environment=environments["producer"]
    )
    wait_socket(Path(environments["producer"]["RI_KNOT_TRACE_HOOK_SOCKET"]))
    queue_cache = lab.root / "cache-queue-full"
    queue_cache.mkdir(exist_ok=True)
    lab.start(
        "resolver",
        [str(kresd), "-n", "-v", "-c", str(kresd_config), str(queue_cache)],
        environment=environments["resolver"],
    )
    wait_for(
        lambda: tcp_connectable(("127.0.0.1", 15354)),
        "Knot Resolver for queue-full failure injection",
    )
    queue_failed = exchange_udp(
        ("127.0.0.1", 15355), dns_query("queue-full.trace.ri", 0x3006), timeout=10
    )
    check_servfail(queue_failed, "Trace queue full test")
    if sqlite_value(queue_database, "SELECT COUNT(*) FROM trace_spool") != 1:
        raise AcceptanceError("Trace queue limit did not retain exactly one durable event")
    if http_status("http://127.0.0.1:19110/readyz") != 503:
        raise AcceptanceError("Trace Adapter remained ready with a full durable spool")
    results["trace_queue_full_fail_closed"] = "passed"

    lab.stop("producer")
    failed = exchange_udp(
        ("127.0.0.1", 15355), dns_query("producer-down.trace.ri", 0x3004)
    )
    check_servfail(failed, "Trace Producer crash test")
    results["producer_crash_fail_closed"] = "passed"

    return results


def secret_scan() -> bool:
    listed = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=REPO,
    )
    files = [item.decode() for item in listed.split(b"\0") if item]
    forbidden_suffixes = (
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        ".keystore",
        ".jks",
        ".db",
        ".sqlite",
        "-wal",
        "-shm",
    )
    forbidden_names = {".env.local", "id_rsa", "id_ed25519"}
    content_patterns = (
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,})"),
        re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        re.compile(rb"https?://[^/@\s]+:[^/@\s]+@"),
        re.compile(
            rb"(?:PRIVATE_KEY|MNEMONIC|PASSWORD|API_KEY)[A-Z0-9_]*"
            rb"[=:][ \t]*(?:0x)?[0-9a-fA-F]{64}"
        ),
    )
    for name in files:
        path = Path(name)
        if path.name in forbidden_names or name.endswith(forbidden_suffixes):
            raise AcceptanceError(f"secret/runtime artifact detected: {name}")
        absolute = REPO / path
        if absolute.is_file() and absolute.stat().st_size <= 16 * 1024 * 1024:
            content = absolute.read_bytes()
            if any(pattern.search(content) for pattern in content_patterns):
                raise AcceptanceError(f"high-confidence secret detected in {name}")

    revisions = run(["git", "rev-list", "HEAD"]).splitlines()
    history_patterns = (
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"(AKIA|ASIA)[A-Z0-9]{16}",
        r"https?://[^/@[:space:]]+:[^/@[:space:]]+@",
        r"(PRIVATE_KEY|MNEMONIC|PASSWORD|API_KEY)[A-Z0-9_]*"
        r"[=:][[:space:]]*(0x)?[0-9a-fA-F]{64}",
    )
    forbidden_history_name = re.compile(
        r"(^|/)(\.env\.local|id_rsa|id_ed25519|"
        r"[^/]+\.(?:db|db-wal|db-shm|sqlite|pem|p12|pfx|keystore|jks|key))$"
    )
    for revision in revisions:
        names = run(["git", "ls-tree", "-r", "--name-only", revision]).splitlines()
        if any(forbidden_history_name.search(name) for name in names):
            raise AcceptanceError(
                "secret/runtime artifact exists in reachable Git history"
            )
        for pattern in history_patterns:
            result = subprocess.run(
                ["git", "grep", "-I", "-q", "-E", "-e", pattern, revision, "--"],
                cwd=REPO,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                raise AcceptanceError(
                    "high-confidence secret material exists in reachable Git history"
                )
            if result.returncode not in (0, 1):
                raise AcceptanceError(
                    f"Git history secret scan failed for revision {revision}"
                )
    diff = run(["git", "diff", "--check"])
    return diff == ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kresd", type=Path, required=True)
    parser.add_argument("--knotd", type=Path, required=True)
    parser.add_argument("--kdig", type=Path, required=True)
    parser.add_argument("--library-path", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if args.concurrency < 32 or args.concurrency > 2048:
        parser.error("--concurrency must be between 32 and 2048")
    for binary in (args.kresd, args.knotd, args.kdig):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"executable is unavailable: {binary}")

    temporary = None
    if args.work_dir:
        root = args.work_dir.resolve()
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="ri-production-trace-")
        root = Path(temporary.name)
    lab = Lab(root, args.library_path)
    results: dict[str, str] = {}
    cleaned = False
    try:
        run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/unit/test_norn_field_delivery.py",
            ],
            timeout=900,
        )
        results["resolver_link_install"] = "passed"
        results["resolver_link_upgrade"] = "passed"
        results["resolver_link_rollback"] = "passed"
        run(["cargo", "build", "--workspace", "--locked"], cwd=RUST, timeout=900)
        binaries = rust_binaries()
        for binary in binaries.values():
            if not binary.is_file():
                raise AcceptanceError(f"Rust binary was not built: {binary}")
        version = run([str(args.kresd), "-V"], environment=lab.environment())
        if RESOLVER_VERSION not in version:
            raise AcceptanceError(f"unexpected Knot Resolver version: {version.strip()}")
        if b"RI_KNOT_TRACE_HOOK_SOCKET" not in args.kresd.read_bytes():
            raise AcceptanceError("Knot Resolver binary does not contain the production Trace hook")
        results["real_resolver"] = "passed"

        authority_config, _ = write_authority_files(root)
        lab.start("authority", [str(args.knotd), "-c", str(authority_config), "-v"])
        wait_for(
            lambda: subprocess.run(
                [str(args.kdig), "@127.0.0.2", "-p", "15353", ".", "SOA"],
                env=lab.environment(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0,
            "DNSSEC authoritative Knot server",
        )
        trust_anchor = discover_trust_anchor(args.kdig, lab)
        (root / "trace.keys").write_text(trust_anchor)
        kresd_config = write_resolver_config(root, trust_anchor)
        seed = seed_lab(root)
        environments = service_environments(root, seed)
        start_data_plane(lab, binaries, environments, args.kresd, kresd_config)
        database = seed / "evidence-v2.db"
        positive, concurrency, cross_talk = test_real_queries(database, args.concurrency)
        results.update(positive)
        results.update(
            test_multi_upstream_failover(
                lab,
                database,
                args.kresd,
                kresd_config,
                trust_anchor,
                environments["resolver"],
            )
        )
        results.update(
            run_negative_tests(
                lab,
                binaries,
                environments,
                args.kresd,
                kresd_config,
                database,
            )
        )
        results["strict_context_binding"] = "passed"
        results["fail_closed"] = "passed"
        sqlite_integrity = sqlite_value(database, "PRAGMA integrity_check")
        if sqlite_integrity != "ok":
            raise AcceptanceError(f"SQLite integrity check failed: {sqlite_integrity}")
        results["sqlite_integrity"] = "passed"
        secrets_clean = secret_scan()
        source_commit = run(["git", "rev-parse", "HEAD"]).strip()
        acceptance = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
            "generated_by": "tools/run_production_trace_acceptance.py",
            "branch": run(["git", "branch", "--show-current"]).strip(),
            "source_commit": source_commit,
            "release_version": RELEASE_VERSION,
            "resolver_name": RESOLVER_NAME,
            "resolver_version": RESOLVER_VERSION,
            "resolver_upstream_commit": RESOLVER_COMMIT,
            "resolver_binary_sha256": sha256(args.kresd),
            "trace_producer_version": TRACE_PRODUCER_VERSION,
            "context_id_mechanism": (
                "random 128-bit trace_id bound to Knot (worker PID, request UID); "
                "Wrapper correlation_id is derived from the exact forwarded DNS wire"
            ),
            "time_window_matching": False,
            "concurrency": concurrency,
            "cross_talk_count": cross_talk,
            "test_scenarios": sorted(results),
            "results": results,
            "failure_closed": all(
                value == "passed"
                for key, value in results.items()
                if "fail_closed" in key or key == "modified_trace_rejected"
            ),
            "installation": {
                "install": "verified-by-field-package-suite",
                "upgrade": "verified-by-field-package-suite",
                "rollback": "verified-by-field-package-suite",
            },
            "sqlite_integrity": sqlite_integrity,
            "secret_scan_clean": secrets_clean,
            "temporary_environment_cleaned": not args.keep,
            "production_trace_ready": False,
        }
        required = {
            "real_resolver",
            "udp_query",
            "tcp_query",
            "same_qname_concurrency",
            "transaction_id_reuse",
            "cache_hit",
            "cname_resolution",
            "strict_context_binding",
            "modified_trace_rejected",
            "agent_unavailable_fail_closed",
            "stale_registry_fail_closed",
            "invalid_identity_fail_closed",
            "producer_crash_fail_closed",
            "resolver_restart",
            "resolver_link_install",
            "resolver_link_upgrade",
            "resolver_link_rollback",
            "udp_to_tcp_fallback",
            "udp_timeout_retry",
            "multi_upstream_failover",
            "trace_queue_full_fail_closed",
            "orphan_cache_trace_fail_closed",
            "fail_closed",
            "sqlite_integrity",
        }
        acceptance["production_trace_ready"] = (
            required.issubset(results)
            and all(results[key] == "passed" for key in required)
            and all(value == "passed" for value in results.values())
            and cross_talk == 0
            and secrets_clean
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(acceptance, indent=2, sort_keys=True) + "\n")
        if not acceptance["production_trace_ready"]:
            raise AcceptanceError("production Trace readiness gate did not pass")
        return 0
    except Exception as error:
        print(f"production Trace acceptance failed: {error}", file=sys.stderr)
        diagnostics = lab.diagnostic_summary()
        if diagnostics:
            print(diagnostics, file=sys.stderr)
        return 1
    finally:
        lab.close()
        if temporary is not None and not args.keep:
            temporary.cleanup()
            cleaned = True
        if args.work_dir and not args.keep:
            shutil.rmtree(root, ignore_errors=True)
            cleaned = True
        if cleaned:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
